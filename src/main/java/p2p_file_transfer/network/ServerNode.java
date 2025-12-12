package p2p_file_transfer.network;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import p2p_file_transfer.model.Packet;

public class ServerNode implements Runnable {
    private int port;
    private boolean isRunning;
    private ServerListener listener;

    private static final String SAVE_DIR = "ReceivedFiles";

    public ServerNode(int port, ServerListener listener) {
        this.port = port;
        this.isRunning = true;
        this.listener = listener;

    }

    @Override
    public void run() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server is listening on port: " + port);

            while (isRunning) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("New connection from: " + clientSocket.getInetAddress());
                new Thread(new ClientHandler(clientSocket)).start();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void stop() {
        isRunning = false;
    }

    private class ClientHandler implements Runnable {
        private Socket socket;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try (DataInputStream in = new DataInputStream(socket.getInputStream())) {
                int type = in.readInt();
                if (type == Packet.TYPE_HELLO) {
                    String message = in.readUTF();
                    if (listener != null) {
                        listener.onMessageReceived(message);
                    }
                } else if (type == Packet.TYPE_FILE) {
                    String fileName = in.readUTF();
                    long fileSize = in.readLong();

                    File saveDir = new File(SAVE_DIR);
                    if (!saveDir.exists()) {
                        saveDir.mkdirs();
                    }

                    File fileDst = new File(saveDir, fileName);
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
                        listener.onMessageReceived("[FILE] Đã nhận file: " + fileName + " (Lưu tại " + SAVE_DIR + ")");
                    }
                }
            } catch (EOFException e) {
                // Client ngắt kết nối
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