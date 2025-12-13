package p2p_file_transfer.network;

import java.io.*;
import java.net.Socket;
import p2p_file_transfer.model.Packet;

public class ClientNode {
    private String myPeerID;
    private String myUsername;

    public ClientNode() {
        this.myPeerID = "UNKNOWN";
        this.myUsername = "Unknown";
    }

    public void setSenderInfo(String peerID, String username) {
        this.myPeerID = peerID;
        this.myUsername = username;
    }

    public void sendText(String destinationIp, int port, String message) {
        new Thread(() -> {
            try (Socket socket = new Socket(destinationIp, port);
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

                out.writeInt(Packet.TYPE_HELLO);
                out.writeUTF(myPeerID); // Sender Peer ID
                out.writeUTF(myUsername); // Sender Username
                out.writeUTF(message); // Message content
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
                out.writeUTF(myPeerID); // Sender Peer ID
                out.writeUTF(myUsername); // Sender Username
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

    /**
     * Callback interface for authentication results.
     */
    public interface AuthCallback {
        void onChallengeReceived();

        void onAuthResult(boolean success);

        void onError(String message);
    }

    /**
     * Sends an authentication request to a peer.
     * The peer will generate a code to display to their user.
     * 
     * @param destinationIp target IP
     * @param port          target port
     * @param callback      callback for auth events
     */
    public void sendAuthRequest(String destinationIp, int port, AuthCallback callback) {
        new Thread(() -> {
            try (Socket socket = new Socket(destinationIp, port);
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    DataInputStream in = new DataInputStream(socket.getInputStream())) {

                socket.setSoTimeout(10000); // 10 second timeout

                out.writeInt(Packet.TYPE_AUTH_REQUEST);
                out.writeUTF(myPeerID);
                out.writeUTF(myUsername);
                out.flush();

                System.out.println("[Auth] Sent auth request to " + destinationIp + ":" + port);

                // Wait for challenge
                int responseType = in.readInt();
                if (responseType == Packet.TYPE_AUTH_CHALLENGE) {
                    String challenge = in.readUTF();
                    System.out.println("[Auth] Received challenge: " + challenge);
                    if (callback != null) {
                        callback.onChallengeReceived();
                    }
                }

            } catch (IOException e) {
                System.err.println("[Auth] Error sending auth request: " + e.getMessage());
                if (callback != null) {
                    callback.onError(e.getMessage());
                }
            }
        }).start();
    }

    /**
     * Sends the authentication code to verify with the peer.
     * 
     * @param destinationIp target IP
     * @param port          target port
     * @param code          the 6-digit code entered by user
     * @param callback      callback for result
     */
    public void sendAuthResponse(String destinationIp, int port, String code, AuthCallback callback) {
        new Thread(() -> {
            try (Socket socket = new Socket(destinationIp, port);
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    DataInputStream in = new DataInputStream(socket.getInputStream())) {

                socket.setSoTimeout(10000);

                out.writeInt(Packet.TYPE_AUTH_RESPONSE);
                out.writeUTF(myPeerID);
                out.writeUTF(code);
                out.flush();

                System.out.println("[Auth] Sent code to " + destinationIp + ":" + port);

                // Wait for result
                int responseType = in.readInt();
                if (responseType == Packet.TYPE_AUTH_RESULT) {
                    boolean success = in.readBoolean();
                    System.out.println("[Auth] Auth result: " + (success ? "SUCCESS" : "FAILED"));
                    if (callback != null) {
                        callback.onAuthResult(success);
                    }
                }

            } catch (IOException e) {
                System.err.println("[Auth] Error sending code: " + e.getMessage());
                if (callback != null) {
                    callback.onError(e.getMessage());
                }
            }
        }).start();
    }
}
