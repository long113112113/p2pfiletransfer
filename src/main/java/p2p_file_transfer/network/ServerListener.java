package p2p_file_transfer.network;

public interface ServerListener {
    void onMessageReceived(String message);
}
