package p2p_file_transfer.network;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

import p2p_file_transfer.model.PeerInfo;

public class PeerDiscoveryService {
    public static final int DISCOVERY_PORT = 9998;
    private static final String DISCOVER_REQUEST = "P2P_DISCOVER";
    private static final String DISCOVER_RESPONSE = "P2P_RESPONSE";
    private static final int TIMEOUT_MS = 2000;

    private DatagramSocket listenerSocket;
    private volatile boolean isListening = false;
    private String myUsername;
    private int myPort;
    private String myIp;

    public PeerDiscoveryService(String username, int port, String myIp) {
        this.myUsername = username;
        this.myPort = port;
        this.myIp = myIp;
    }

    public void startListener() {
        if (isListening)
            return;

        isListening = true;
        Thread listenerThread = new Thread(() -> {
            try {
                listenerSocket = new DatagramSocket(DISCOVERY_PORT);
                byte[] buffer = new byte[256];

                while (isListening) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    try {
                        listenerSocket.receive(packet);
                        String received = new String(packet.getData(), 0, packet.getLength());

                        if (received.equals(DISCOVER_REQUEST)) {
                            String response = DISCOVER_RESPONSE + "|" + myUsername + "|" + myPort;
                            byte[] responseData = response.getBytes();
                            DatagramPacket responsePacket = new DatagramPacket(
                                    responseData,
                                    responseData.length,
                                    packet.getAddress(),
                                    packet.getPort());
                            listenerSocket.send(responsePacket);
                        }
                    } catch (SocketTimeoutException e) {
                        // ignore
                    }
                }
            } catch (IOException e) {
                if (isListening) {
                    e.printStackTrace();
                }
            } finally {
                if (listenerSocket != null && !listenerSocket.isClosed()) {
                    listenerSocket.close();
                }
            }
        });
        listenerThread.setDaemon(true);
        listenerThread.start();
    }

    public void stopListener() {
        isListening = false;
        if (listenerSocket != null && !listenerSocket.isClosed()) {
            listenerSocket.close();
        }
    }

    public void discoverPeers(Consumer<Set<PeerInfo>> callback) {
        Thread discoverThread = new Thread(() -> {
            Set<PeerInfo> foundPeers = new HashSet<>();

            try (DatagramSocket socket = new DatagramSocket()) {
                socket.setBroadcast(true);
                socket.setSoTimeout(TIMEOUT_MS);

                byte[] sendData = DISCOVER_REQUEST.getBytes();
                DatagramPacket sendPacket = new DatagramPacket(
                        sendData,
                        sendData.length,
                        InetAddress.getByName("255.255.255.255"),
                        DISCOVERY_PORT);
                socket.send(sendPacket);

                byte[] receiveBuffer = new byte[256];
                long startTime = System.currentTimeMillis();

                while (System.currentTimeMillis() - startTime < TIMEOUT_MS) {
                    try {
                        DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
                        socket.receive(receivePacket);

                        String received = new String(receivePacket.getData(), 0, receivePacket.getLength());
                        if (received.startsWith(DISCOVER_RESPONSE)) {
                            String[] parts = received.split("\\|");
                            if (parts.length == 3) {
                                String peerIp = receivePacket.getAddress().getHostAddress();
                                String peerUsername = parts[1];
                                int peerPort = Integer.parseInt(parts[2]);

                                if (!peerIp.equals(myIp)) {
                                    foundPeers.add(new PeerInfo(peerIp, peerUsername, peerPort));
                                }
                            }
                        }
                    } catch (SocketTimeoutException e) {
                        break;
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

            callback.accept(foundPeers);
        });
        discoverThread.setDaemon(true);
        discoverThread.start();
    }
}
