package p2p_file_transfer.model;

import java.security.PublicKey;

public class PeerInfo {
    private String ip;
    private String username;
    private int port;
    private String peerID;
    private PublicKey publicKey;
    private AuthenticationState authState = AuthenticationState.UNKNOWN;

    public PeerInfo(String ip, String username, int port, String peerID) {
        this.ip = ip;
        this.username = username;
        this.port = port;
        this.peerID = peerID;
        this.publicKey = null;
    }

    public PeerInfo(String ip, String username, int port, String peerID, PublicKey publicKey) {
        this.ip = ip;
        this.username = username;
        this.port = port;
        this.peerID = peerID;
        this.publicKey = publicKey;
    }

    public String getIp() {
        return ip;
    }

    public String getUsername() {
        return username;
    }

    public int getPort() {
        return port;
    }

    public String getPeerID() {
        return peerID;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public AuthenticationState getAuthState() {
        return authState;
    }

    public void setAuthState(AuthenticationState authState) {
        this.authState = authState;
    }

    @Override
    public String toString() {
        return username + " [" + peerID + "] (" + ip + ")";
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null || getClass() != obj.getClass())
            return false;
        PeerInfo other = (PeerInfo) obj;
        return ip.equals(other.ip) && port == other.port;
    }

    @Override
    public int hashCode() {
        return ip.hashCode() * 31 + port;
    }
}
