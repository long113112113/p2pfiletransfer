package p2p_file_transfer.manager;

import p2p_file_transfer.model.Peer;
import java.util.ArrayList;
import java.util.List;

public class PeerManager {
    private static PeerManager instance;
    private List<Peer> peers;

    // Init list
    private PeerManager() {
        peers = new ArrayList<>();
    }

    public static PeerManager getInstance() {
        if (instance == null) {
            instance = new PeerManager();
        }
        return instance;
    }

    public void addPeer(Peer peer) {
        for (Peer p : peers) {
            if (p.getHost().equals(peer.getHost())) {
                return;
            }
        }
        peers.add(peer);
        System.out.println("Added peer: " + peer.getName());
    }

    public void removePeer(String host) {
        peers.removeIf(p -> p.getHost().equals(host));
    }

    public List<Peer> getPeers() {
        return peers;
    }

}
