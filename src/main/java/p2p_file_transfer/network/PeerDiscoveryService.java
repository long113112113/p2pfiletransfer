package p2p_file_transfer.network;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import p2p_file_transfer.model.PeerInfo;

public class PeerDiscoveryService {
    public static final int DISCOVERY_PORT = 9998;
    private static final String DISCOVER_REQUEST = "P2P_DISCOVER";
    private static final String DISCOVER_RESPONSE = "P2P_RESPONSE";
    private static final int TIMEOUT_MS = 3000;

    private DatagramSocket listenerSocket;
    private volatile boolean isListening = false;
    private String myUsername;
    private int myPort;

    private String myPeerID;

    private Consumer<PeerInfo> peerDiscoveredCallback;

    public PeerDiscoveryService(String username, int port, String peerID) {
        this.myUsername = username;
        this.myPort = port;

        this.myPeerID = peerID;
        System.out
                .println("[Discovery] Initialized - Username: " + username + ", Port: " + port + ", PeerID: " + peerID);
    }

    public void setOnPeerDiscovered(Consumer<PeerInfo> callback) {
        this.peerDiscoveredCallback = callback;
    }

    public void startListener() {
        if (isListening) {
            System.out.println("[Discovery] Listener already running");
            return;
        }

        isListening = true;
        Thread listenerThread = new Thread(() -> {
            try {
                listenerSocket = new DatagramSocket(DISCOVERY_PORT);
                listenerSocket.setBroadcast(true);
                System.out.println("[Discovery] Listener started on port " + DISCOVERY_PORT);
                byte[] buffer = new byte[1024]; // Increased buffer size for metadata

                while (isListening) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    try {
                        listenerSocket.receive(packet);
                        String received = new String(packet.getData(), 0, packet.getLength());
                        String senderIp = packet.getAddress().getHostAddress();

                        System.out.println(
                                "[Discovery] Received: '" + received + "' from " + senderIp + ":" + packet.getPort());

                        if (received.startsWith(DISCOVER_REQUEST)) {
                            // Try to parse sender info from request: P2P_DISCOVER|username|port|peerID
                            if (received.contains("|")) {
                                String[] parts = received.split("\\|");
                                if (parts.length >= 4) {
                                    String peerUsername = parts[1];
                                    int peerPort = Integer.parseInt(parts[2]);
                                    String peerID = parts[3];

                                    if (!peerID.equals(myPeerID)) {
                                        PeerInfo newPeer = new PeerInfo(senderIp, peerUsername, peerPort, peerID);
                                        if (peerDiscoveredCallback != null) {
                                            peerDiscoveredCallback.accept(newPeer);
                                        }
                                    }
                                }
                            }

                            // Response format: P2P_RESPONSE|username|port|peerID
                            String response = DISCOVER_RESPONSE + "|" + myUsername + "|" + myPort + "|" + myPeerID;
                            byte[] responseData = response.getBytes();
                            DatagramPacket responsePacket = new DatagramPacket(
                                    responseData,
                                    responseData.length,
                                    packet.getAddress(),
                                    packet.getPort());
                            listenerSocket.send(responsePacket);
                            System.out.println("[Discovery] Sent response to " + senderIp + ":" + packet.getPort());
                        }
                    } catch (SocketTimeoutException e) {
                        // ignore timeout
                    }
                }
            } catch (SocketException e) {
                System.err.println("[Discovery] Failed to start listener: " + e.getMessage());
                System.err.println("[Discovery] Port " + DISCOVERY_PORT + " may already be in use!");
            } catch (IOException e) {
                if (isListening) {
                    e.printStackTrace();
                }
            } finally {
                if (listenerSocket != null && !listenerSocket.isClosed()) {
                    listenerSocket.close();
                }
                System.out.println("[Discovery] Listener stopped");
            }
        });
        listenerThread.setDaemon(true);
        listenerThread.setName("PeerDiscoveryListener");
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
            System.out.println("[Discovery] Starting peer discovery...");

            try (DatagramSocket socket = new DatagramSocket()) {
                socket.setBroadcast(true);
                socket.setSoTimeout(500);

                // Send request with MY info: P2P_DISCOVER|username|port|peerID
                String requestMsg = DISCOVER_REQUEST + "|" + myUsername + "|" + myPort + "|" + myPeerID;
                byte[] sendData = requestMsg.getBytes();

                List<InetAddress> broadcastAddresses = getBroadcastAddresses();
                System.out.println("[Discovery] Found " + broadcastAddresses.size() + " broadcast addresses");

                for (InetAddress broadcastAddr : broadcastAddresses) {
                    try {
                        DatagramPacket sendPacket = new DatagramPacket(
                                sendData,
                                sendData.length,
                                broadcastAddr,
                                DISCOVERY_PORT);
                        socket.send(sendPacket);
                        System.out.println("[Discovery] Sent DISCOVER to " + broadcastAddr.getHostAddress());
                    } catch (IOException e) {
                        System.err.println("[Discovery] Failed to send to " + broadcastAddr + ": " + e.getMessage());
                    }
                }

                byte[] receiveBuffer = new byte[1024];
                long startTime = System.currentTimeMillis();

                while (System.currentTimeMillis() - startTime < TIMEOUT_MS) {
                    try {
                        DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
                        socket.receive(receivePacket);

                        String received = new String(receivePacket.getData(), 0, receivePacket.getLength());
                        String senderIp = receivePacket.getAddress().getHostAddress();

                        System.out.println("[Discovery] Got response: '" + received + "' from " + senderIp);

                        if (received.startsWith(DISCOVER_RESPONSE)) {
                            String[] parts = received.split("\\|");
                            // Format: P2P_RESPONSE|username|port|peerID
                            if (parts.length >= 4) {
                                String peerIp = senderIp;
                                String peerUsername = parts[1];
                                int peerPort = Integer.parseInt(parts[2]);
                                String peerID = parts[3];

                                if (!peerID.equals(myPeerID)) { // Use ID check instead of IP
                                    PeerInfo peer = new PeerInfo(peerIp, peerUsername, peerPort, peerID);
                                    foundPeers.add(peer);
                                    System.out.println("[Discovery] Found peer: " + peer);

                                    // Also notify the active listener callback if set,
                                    // so UI updates immediately even during scan
                                    if (peerDiscoveredCallback != null) {
                                        peerDiscoveredCallback.accept(peer);
                                    }
                                } else {
                                    System.out.println("[Discovery] Ignoring self response");
                                }
                            }
                        }
                    } catch (SocketTimeoutException e) {
                        // Continue listening
                    }
                }
            } catch (IOException e) {
                System.err.println("[Discovery] Error during discovery: " + e.getMessage());
                e.printStackTrace();
            }

            System.out.println("[Discovery] Discovery complete. Found " + foundPeers.size() + " peers");
            callback.accept(foundPeers);
        });
        discoverThread.setDaemon(true);
        discoverThread.setName("PeerDiscoveryScanner");
        discoverThread.start();
    }

    private List<InetAddress> getBroadcastAddresses() {
        List<InetAddress> broadcastList = new ArrayList<>();

        try {
            broadcastList.add(InetAddress.getByName("255.255.255.255"));
        } catch (Exception e) {
            // ignore
        }

        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();

                if (networkInterface.isLoopback() || !networkInterface.isUp()) {
                    continue;
                }

                for (InterfaceAddress interfaceAddress : networkInterface.getInterfaceAddresses()) {
                    InetAddress broadcast = interfaceAddress.getBroadcast();
                    if (broadcast != null) {
                        broadcastList.add(broadcast);
                    }
                }
            }
        } catch (SocketException e) {
            System.err.println("[Discovery] Error getting network interfaces: " + e.getMessage());
        }

        return broadcastList;
    }
}
