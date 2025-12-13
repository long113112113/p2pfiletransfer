package p2p_file_transfer.network;

public interface ServerListener {
    void onMessageReceived(String message);

    /**
     * Called when a peer requests authentication.
     * 
     * @param peerID   the requesting peer's ID
     * @param username the requesting peer's username
     * @param code     the 6-digit code to display to user
     */
    void onAuthRequest(String peerID, String username, String code);

    /**
     * Called when authentication verification is complete.
     * 
     * @param peerID  the peer that was verified
     * @param success true if authentication succeeded
     */
    void onAuthResult(String peerID, boolean success);
}
