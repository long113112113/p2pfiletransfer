package p2p_file_transfer.network;

import java.io.*;
import java.net.Socket;
import p2p_file_transfer.model.Packet;

public class ClientNode {
    public void sendText(String destinationIp, int port, String message) {
        // Create new thread (send message)
        new Thread(() -> {
            try (Socket socket = new Socket(destinationIp, port);
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

                out.writeInt(Packet.TYPE_HELLO);
                out.writeUTF(message);
                out.flush();

            } catch (IOException e) {
                System.err.println("Client: Error " + e.getMessage());
            }
        }).start();
    }

    public void sendFile(String destinationIp, int port, File file) {
        new Thread(() -> {
            try (Socket socket = new Socket(destinationIp, port);
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    FileInputStream fileIn = new FileInputStream(file)) {

                out.writeInt(Packet.TYPE_FILE);

                out.writeUTF(file.getName());
                out.writeLong(file.length());

                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fileIn.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }

                out.flush();
                System.out.println("Client: File sent: " + file.getName());

            } catch (IOException e) {
                System.err.println("Client: Error " + e.getMessage());
            }
        }).start();
    }
}
