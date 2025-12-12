package p2p_file_transfer.model;

public class PeerInfo {
    private String ip;
    private String username;
    private int port;
    private String peerID;

    public PeerInfo(String ip, String username, int port, String peerID) {
        this.ip = ip;
        this.username = username;
        this.port = port;
        this.peerID = peerID;
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
