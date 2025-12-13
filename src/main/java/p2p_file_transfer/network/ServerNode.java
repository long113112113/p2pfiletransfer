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

    private static final String SAVE_DIR = "ReceivedFiles";

    public ServerNode(int port, ServerListener listener) {
        this.port = port;
        this.isRunning = true;
        this.listener = listener;
    }

    @Override
    public void run() {
        try {
            serverSocket = new ServerSocket(port);
            serverSocket.setSoTimeout(1000); // 1 second timeout for graceful shutdown check
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
            try (DataInputStream in = new DataInputStream(socket.getInputStream())) {
                int type = in.readInt();

                if (type == Packet.TYPE_HELLO) {
                    String senderPeerID = in.readUTF();
                    String senderUsername = in.readUTF();
                    String message = in.readUTF();

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
    }
}