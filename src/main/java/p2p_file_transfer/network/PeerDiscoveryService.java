package p2p_file_transfer.network;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import p2p_file_transfer.model.PeerInfo;
import p2p_file_transfer.util.CryptoUtils;

public class PeerDiscoveryService {
    public static final int DISCOVERY_PORT = 9998;
    private static final String DISCOVER_REQUEST = "P2P_DISCOVER";
    private static final String DISCOVER_RESPONSE = "P2P_RESPONSE";
    private static final int TIMEOUT_MS = 3000;
    private static final long MAX_MESSAGE_AGE_MS = 30000; // 30 seconds

    private DatagramSocket listenerSocket;
    private volatile boolean isListening = false;
    private String myUsername;
    private int myPort;
    private String myPeerID;

    // Cryptographic keys for signing
    private PrivateKey myPrivateKey;
    private PublicKey myPublicKey;

    private Consumer<PeerInfo> peerDiscoveredCallback;

    public PeerDiscoveryService(String username, int port, String peerID, PrivateKey privateKey, PublicKey publicKey) {
        this.myUsername = username;
        this.myPort = port;
        this.myPeerID = peerID;
        this.myPrivateKey = privateKey;
        this.myPublicKey = publicKey;
        System.out
                .println("[Discovery] Initialized - Username: " + username + ", Port: " + port + ", PeerID: " + peerID);
        System.out.println("[Discovery] Cryptographic signing: " + (privateKey != null ? "ENABLED" : "DISABLED"));
    }

    public void setOnPeerDiscovered(Consumer<PeerInfo> callback) {
        this.peerDiscoveredCallback = callback;
    }

    /**
     * Creates a signed discovery message.
     * Format: TYPE|username|port|peerID|timestamp|publicKeyBase64|signature
     */
    private String createSignedMessage(String messageType) {
        long timestamp = System.currentTimeMillis();
        String publicKeyBase64 = CryptoUtils.encodePublicKey(myPublicKey);

        // Message to sign (everything except signature)
        String messageToSign = messageType + "|" + myUsername + "|" + myPort + "|" + myPeerID + "|" + timestamp + "|"
                + publicKeyBase64;

        String signature = "";
        if (myPrivateKey != null) {
            try {
                signature = CryptoUtils.sign(messageToSign, myPrivateKey);
            } catch (Exception e) {
                System.err.println("[Security] Failed to sign message: " + e.getMessage());
            }
        }

        return messageToSign + "|" + signature;
    }

    /**
     * Validates a signed discovery message.
     * Returns the decoded PeerInfo if valid, null otherwise.
     */
    private PeerInfo validateSignedMessage(String received, String senderIp, String expectedType) {
        try {
            String[] parts = received.split("\\|");
            // Expected format:
            // TYPE|username|port|peerID|timestamp|publicKeyBase64|signature
            if (parts.length < 7) {
                System.err.println("[Security] Invalid message format: not enough parts (" + parts.length + ")");
                return null;
            }

            String type = parts[0];
            String peerUsername = parts[1];
            int peerPort = Integer.parseInt(parts[2]);
            String peerID = parts[3];
            long timestamp = Long.parseLong(parts[4]);
            String publicKeyBase64 = parts[5];
            String signature = parts[6];

            // 1. Check message type
            if (!type.equals(expectedType)) {
                return null;
            }

            // 2. Check timestamp (reject old messages - prevent replay attacks)
            long age = System.currentTimeMillis() - timestamp;
            if (age > MAX_MESSAGE_AGE_MS || age < -MAX_MESSAGE_AGE_MS) {
                System.err.println("[Security] Rejected: Message too old (" + age + "ms) - possible replay attack");
                return null;
            }

            // 3. Decode public key
            PublicKey peerPublicKey = CryptoUtils.decodePublicKey(publicKeyBase64);
            if (peerPublicKey == null) {
                System.err.println("[Security] Rejected: Failed to decode public key");
                return null;
            }

            // 4. CRITICAL: Verify PeerID matches hash of PublicKey (cryptographic binding)
            if (!CryptoUtils.verifyPeerIdentity(peerID, peerPublicKey)) {
                System.err.println("[Security] REJECTED: PeerID does not match PublicKey hash - FORGERY ATTEMPT from "
                        + senderIp);
                return null;
            }

            // 5. Skip self
            if (peerID.equals(myPeerID)) {
                return null;
            }

            // 6. Verify signature
            String messageToVerify = type + "|" + peerUsername + "|" + peerPort + "|" + peerID + "|" + timestamp + "|"
                    + publicKeyBase64;
            if (!CryptoUtils.verify(messageToVerify, signature, peerPublicKey)) {
                System.err.println("[Security] REJECTED: Invalid signature from " + senderIp + " - FORGERY ATTEMPT");
                return null;
            }

            // All checks passed - create verified PeerInfo
            System.out.println("[Security] Verified peer: " + peerUsername + " [" + peerID + "]");
            return new PeerInfo(senderIp, peerUsername, peerPort, peerID, peerPublicKey);

        } catch (NumberFormatException e) {
            System.err.println("[Security] Invalid message format: " + e.getMessage());
            return null;
        }
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
                byte[] buffer = new byte[4096]; // Increased for PublicKey + signature

                while (isListening) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    try {
                        listenerSocket.receive(packet);
                        String received = new String(packet.getData(), 0, packet.getLength());
                        String senderIp = packet.getAddress().getHostAddress();

                        System.out.println("[Discovery] Received message from " + senderIp + ":" + packet.getPort());

                        if (received.startsWith(DISCOVER_REQUEST)) {
                            // Validate and extract peer info
                            PeerInfo newPeer = validateSignedMessage(received, senderIp, DISCOVER_REQUEST);

                            if (newPeer != null) {
                                // Notify callback about new verified peer
                                if (peerDiscoveredCallback != null) {
                                    peerDiscoveredCallback.accept(newPeer);
                                }
                            }

                            // Send signed response (even if validation failed - they might be new peer)
                            if (myPrivateKey != null && myPublicKey != null) {
                                String response = createSignedMessage(DISCOVER_RESPONSE);
                                byte[] responseData = response.getBytes();
                                DatagramPacket responsePacket = new DatagramPacket(
                                        responseData,
                                        responseData.length,
                                        packet.getAddress(),
                                        packet.getPort());
                                listenerSocket.send(responsePacket);
                                System.out.println("[Discovery] Sent signed response to " + senderIp);
                            }
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

                // Create signed discovery request
                String requestMsg = createSignedMessage(DISCOVER_REQUEST);
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
                        System.out.println("[Discovery] Sent signed DISCOVER to " + broadcastAddr.getHostAddress());
                    } catch (IOException e) {
                        System.err.println("[Discovery] Failed to send to " + broadcastAddr + ": " + e.getMessage());
                    }
                }

                byte[] receiveBuffer = new byte[4096]; // Increased for PublicKey + signature
                long startTime = System.currentTimeMillis();

                while (System.currentTimeMillis() - startTime < TIMEOUT_MS) {
                    try {
                        DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
                        socket.receive(receivePacket);

                        String received = new String(receivePacket.getData(), 0, receivePacket.getLength());
                        String senderIp = receivePacket.getAddress().getHostAddress();

                        System.out.println("[Discovery] Got response from " + senderIp);

                        if (received.startsWith(DISCOVER_RESPONSE)) {
                            // Validate signed response
                            PeerInfo peer = validateSignedMessage(received, senderIp, DISCOVER_RESPONSE);

                            if (peer != null) {
                                foundPeers.add(peer);
                                System.out.println("[Discovery] Found verified peer: " + peer);

                                if (peerDiscoveredCallback != null) {
                                    peerDiscoveredCallback.accept(peer);
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

            System.out.println("[Discovery] Discovery complete. Found " + foundPeers.size() + " verified peers");
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
