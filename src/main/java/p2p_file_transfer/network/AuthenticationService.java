package p2p_file_transfer.network;

import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages peer authentication using 6-digit pairing codes.
 * Codes expire after CODE_EXPIRY_MS milliseconds.
 */
public class AuthenticationService {

    private static final int CODE_LENGTH = 6;
    private static final long CODE_EXPIRY_MS = 60000; // 60 seconds

    private final SecureRandom secureRandom = new SecureRandom();

    // PeerID -> PendingAuth (code + timestamp)
    private final Map<String, PendingAuth> pendingAuths = new ConcurrentHashMap<>();

    // Set of authenticated peer IDs
    private final Set<String> authenticatedPeers = ConcurrentHashMap.newKeySet();

    /**
     * Generates a random 6-digit pairing code.
     * 
     * @return 6-digit numeric string (e.g., "482916")
     */
    public String generatePairingCode() {
        int code = secureRandom.nextInt(900000) + 100000; // 100000-999999
        return String.valueOf(code);
    }

    /**
     * Stores a pending authentication request with the generated code.
     * 
     * @param peerID the peer requesting authentication
     * @param code   the 6-digit code to verify
     */
    public void storePendingAuth(String peerID, String code) {
        pendingAuths.put(peerID, new PendingAuth(code, System.currentTimeMillis()));
        System.out.println("[Auth] Stored pending auth for " + peerID + " with code " + code);
    }

    /**
     * Verifies the code submitted by a peer.
     * 
     * @param peerID        the peer submitting the code
     * @param submittedCode the code to verify
     * @return true if code is correct and not expired, false otherwise
     */
    public boolean verifyCode(String peerID, String submittedCode) {
        PendingAuth pending = pendingAuths.get(peerID);

        if (pending == null) {
            System.out.println("[Auth] No pending auth found for " + peerID);
            return false;
        }

        // Check expiry
        long age = System.currentTimeMillis() - pending.timestamp;
        if (age > CODE_EXPIRY_MS) {
            System.out.println("[Auth] Code expired for " + peerID + " (age: " + age + "ms)");
            pendingAuths.remove(peerID);
            return false;
        }

        // Check code match
        boolean matches = pending.code.equals(submittedCode);
        if (matches) {
            pendingAuths.remove(peerID);
            System.out.println("[Auth] Code verified for " + peerID);
        } else {
            System.out.println(
                    "[Auth] Invalid code from " + peerID + ": expected " + pending.code + ", got " + submittedCode);
        }

        return matches;
    }

    /**
     * Adds a peer to the authenticated set.
     * 
     * @param peerID the peer to trust
     */
    public void addAuthenticatedPeer(String peerID) {
        authenticatedPeers.add(peerID);
        System.out.println("[Auth] Peer " + peerID + " added to authenticated list");
    }

    /**
     * Removes a peer from the authenticated set.
     * 
     * @param peerID the peer to remove
     */
    public void removeAuthenticatedPeer(String peerID) {
        authenticatedPeers.remove(peerID);
        pendingAuths.remove(peerID);
    }

    /**
     * Checks if a peer is authenticated.
     * 
     * @param peerID the peer to check
     * @return true if peer is in the authenticated set
     */
    public boolean isAuthenticated(String peerID) {
        return authenticatedPeers.contains(peerID);
    }

    /**
     * Gets the set of all authenticated peers.
     * 
     * @return unmodifiable view of authenticated peer IDs
     */
    public Set<String> getAuthenticatedPeers() {
        return Set.copyOf(authenticatedPeers);
    }

    /**
     * Clears all pending authentications (e.g., on shutdown).
     */
    public void clearPending() {
        pendingAuths.clear();
    }

    /**
     * Internal class to hold pending authentication data.
     */
    private static class PendingAuth {
        final String code;
        final long timestamp;

        PendingAuth(String code, long timestamp) {
            this.code = code;
            this.timestamp = timestamp;
        }
    }
}
