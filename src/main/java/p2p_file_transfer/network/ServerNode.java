package p2p_file_transfer.network;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

import p2p_file_transfer.model.Packet;

public class ServerNode implements Runnable {
    private int port;
    private volatile boolean isRunning;
    private ServerListener listener;
    private ServerSocket serverSocket;

    // Authentication Service
    private AuthenticationService authService;

    private static final String SAVE_DIR = "ReceivedFiles";

    public ServerNode(int port, ServerListener listener) {
        this.port = port;
        this.isRunning = true;
        this.listener = listener;
        this.authService = new AuthenticationService();
    }

    public AuthenticationService getAuthService() {
        return authService;
    }

    @Override
    public void run() {
        try {
            serverSocket = new ServerSocket(port);
            serverSocket.setSoTimeout(1000);
            System.out.println("Server is listening on port: " + port);

            while (isRunning) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("New connection from: " + clientSocket.getInetAddress());
                    Thread handlerThread = new Thread(new ClientHandler(clientSocket));
                    handlerThread.setName("ClientHandler-" + clientSocket.getInetAddress());
                    handlerThread.start();
                } catch (java.net.SocketTimeoutException e) {
                    // Timeout occurred, check if still running and continue
                    continue;
                }
            }

        } catch (IOException e) {
            if (isRunning) {
                e.printStackTrace();
            }
        } finally {
            closeServerSocket();
            System.out.println("Server stopped on port: " + port);
        }
    }

    public void stop() {
        isRunning = false;
        closeServerSocket();
    }

    private void closeServerSocket() {
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                // Ignore close exception
            }
        }
    }

    /**
     * Sanitize filename to prevent Path Traversal attacks.
     * Uses Java NIO Paths API for reliable path component extraction.
     * 
     * @param fileName the original filename from network
     * @return safe filename or null if filename is malicious
     */
    private String sanitizeFileName(String fileName) {
        if (fileName == null || fileName.isEmpty()) {
            return null;
        }

        try {
            // Remove null bytes (used in some attacks)
            fileName = fileName.replace("\0", "");

            // Use Java NIO to extract only the filename component
            // This handles both Windows and Unix paths correctly
            java.nio.file.Path path = java.nio.file.Paths.get(fileName);
            java.nio.file.Path fileNamePath = path.getFileName();

            if (fileNamePath == null) {
                return null;
            }

            String safeName = fileNamePath.toString();

            // Additional checks
            if (safeName.isEmpty() || safeName.equals(".") || safeName.equals("..")) {
                return null;
            }

            // Reject hidden files (starting with .)
            if (safeName.startsWith(".")) {
                return null;
            }

            return safeName;
        } catch (java.nio.file.InvalidPathException e) {
            // Invalid path - reject
            System.err.println("[Security] Invalid path rejected: " + fileName);
            return null;
        }
    }

    private class ClientHandler implements Runnable {
        private Socket socket;

        public ClientHandler(Socket socket) {
            this.socket = socket;
            try {
                // Set timeout to 5 seconds to prevent hanging on read
                this.socket.setSoTimeout(5000);
            } catch (java.net.SocketException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void run() {
            try (DataInputStream in = new DataInputStream(socket.getInputStream());
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
                int type = in.readInt();

                // Handle Authentication Packets
                if (type == Packet.TYPE_AUTH_REQUEST) {
                    handleAuthRequest(in, out);
                    return;
                } else if (type == Packet.TYPE_AUTH_RESPONSE) {
                    handleAuthResponse(in, out);
                    return;
                }

                // For HELLO and FILE, check if sender is authenticated
                if (type == Packet.TYPE_HELLO) {
                    String senderPeerID = in.readUTF();
                    String senderUsername = in.readUTF();
                    String message = in.readUTF();

                    // Check authentication
                    if (!authService.isAuthenticated(senderPeerID)) {
                        System.out.println("[Security] Blocked message from unauthenticated peer: " + senderPeerID);
                        if (listener != null) {
                            listener.onMessageReceived("[Security] Blocked message from unauthenticated peer: "
                                    + senderUsername + " [" + senderPeerID + "]. Request authentication first.");
                        }
                        return;
                    }

                    if (listener != null) {
                        // Format: "senderUsername [senderPeerID]: message"
                        String formattedMessage = senderUsername + " [" + senderPeerID + "]: " + message;
                        listener.onMessageReceived(formattedMessage);
                    }
                } else if (type == Packet.TYPE_FILE) {
                    String senderPeerID = in.readUTF();
                    String senderUsername = in.readUTF();
                    String fileName = in.readUTF();
                    long fileSize = in.readLong();

                    // Check authentication
                    if (!authService.isAuthenticated(senderPeerID)) {
                        System.out.println("[Security] Blocked file from unauthenticated peer: " + senderPeerID);
                        if (listener != null) {
                            listener.onMessageReceived("[Security] Blocked file from unauthenticated peer: "
                                    + senderUsername + " [" + senderPeerID + "]. Request authentication first.");
                        }
                        // Drain the file data to prevent socket issues
                        long remaining = fileSize;
                        byte[] buffer = new byte[4096];
                        while (remaining > 0) {
                            int toRead = (int) Math.min(buffer.length, remaining);
                            int read = in.read(buffer, 0, toRead);
                            if (read == -1)
                                break;
                            remaining -= read;
                        }
                        return;
                    }

                    // Sanitize filename to prevent Path Traversal attacks
                    String safeFileName = sanitizeFileName(fileName);
                    if (safeFileName == null || safeFileName.isEmpty()) {
                        System.err.println("[Security] Rejected malicious filename: " + fileName);
                        if (listener != null) {
                            listener.onMessageReceived(
                                    "[Security] Rejected file with invalid name from " + senderUsername);
                        }
                        return;
                    }

                    File saveDir = new File(SAVE_DIR);
                    if (!saveDir.exists()) {
                        saveDir.mkdirs();
                    }

                    File fileDst = new File(saveDir, safeFileName);

                    // Double-check: ensure final path is still inside SAVE_DIR
                    if (!fileDst.getCanonicalPath().startsWith(saveDir.getCanonicalPath())) {
                        System.err.println("[Security] Path traversal attempt detected: " + fileName);
                        if (listener != null) {
                            listener.onMessageReceived(
                                    "[Security] Blocked path traversal attempt from " + senderUsername);
                        }
                        return;
                    }

                    try (FileOutputStream fileOut = new FileOutputStream(fileDst)) {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        long totalRead = 0;

                        while (totalRead < fileSize && (bytesRead = in.read(buffer)) != -1) {
                            fileOut.write(buffer, 0, bytesRead);
                            totalRead += bytesRead;
                        }
                    }

                    if (listener != null) {
                        String formattedMessage = senderUsername + " [" + senderPeerID + "]: [FILE] " + fileName
                                + " (Saved to " + SAVE_DIR + ")";
                        listener.onMessageReceived(formattedMessage);
                    }
                }
            } catch (EOFException e) {
                // Client disconnected
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                }
            }
        }

        /**
         * Handles incoming authentication request.
         * Generates a 6-digit code and notifies UI to display it.
         */
        private void handleAuthRequest(DataInputStream in, DataOutputStream out) throws IOException {
            String requesterPeerID = in.readUTF();
            String requesterUsername = in.readUTF();

            // Generate pairing code
            String code = authService.generatePairingCode();
            authService.storePendingAuth(requesterPeerID, code);

            System.out.println("[Auth] Received auth request from " + requesterUsername + " [" + requesterPeerID + "]");

            // Notify UI to display the code
            if (listener != null) {
                listener.onAuthRequest(requesterPeerID, requesterUsername, code);
            }

            // Send challenge response (just acknowledge)
            out.writeInt(Packet.TYPE_AUTH_CHALLENGE);
            out.writeUTF("CHALLENGE_SENT");
            out.flush();
        }

        /**
         * Handles incoming authentication response (code verification).
         */
        private void handleAuthResponse(DataInputStream in, DataOutputStream out) throws IOException {
            String peerID = in.readUTF();
            String submittedCode = in.readUTF();

            System.out.println("[Auth] Received code from " + peerID + ": " + submittedCode);

            boolean success = authService.verifyCode(peerID, submittedCode);
            if (success) {
                authService.addAuthenticatedPeer(peerID);
            }

            // Send result
            out.writeInt(Packet.TYPE_AUTH_RESULT);
            out.writeBoolean(success);
            out.flush();

            // Notify UI
            if (listener != null) {
                listener.onAuthResult(peerID, success);
            }
        }
    }
}
