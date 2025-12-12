package p2p_file_transfer.model;

import java.io.Serializable;

public class Peer implements Serializable {
    private String name;
    private String host;
    private int port;

    public Peer(String name, String host, int port) {
        this.name = name;
        this.host = host;
        this.port = port;
    }

    public String getName() {
        return name;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    @Override
    public String toString() {
        return name + " (" + host + ":" + port + ")";
    }

}
