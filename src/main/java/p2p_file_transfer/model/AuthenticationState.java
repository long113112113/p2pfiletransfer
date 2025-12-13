package p2p_file_transfer.model;

/**
 * Represents the authentication state of a peer connection.
 */
public enum AuthenticationState {
    /** Peer has not been authenticated yet */
    UNKNOWN,

    /** Authentication request sent, waiting for code verification */
    PENDING,

    /** Peer has been successfully authenticated */
    AUTHENTICATED,

    /** Authentication was rejected or failed */
    REJECTED
}
