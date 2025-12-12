package p2p_file_transfer.manager;

import java.security.PrivateKey;
import java.security.PublicKey;

public class SessionManager {
    private static SessionManager instance;

    private String username;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private SessionManager() {
        // Private constructor to enforce Singleton pattern
    }

    public static synchronized SessionManager getInstance() {
        if (instance == null) {
            instance = new SessionManager();
        }
        return instance;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void clearSession() {
        this.username = null;
        this.privateKey = null;
        this.publicKey = null;
    }
}
