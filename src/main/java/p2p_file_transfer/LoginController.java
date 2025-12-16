package p2p_file_transfer;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import p2p_file_transfer.util.CryptoUtils;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import p2p_file_transfer.manager.SessionManager;

public class LoginController {

    @FXML
    private TextField usernameField;

    @FXML
    private PasswordField passwordField;

    @FXML
    private Label statusLabel;

    @FXML
    private void handleLogin(ActionEvent event) {
        String username = usernameField.getText().trim();
        String password = passwordField.getText();

        if (username.isEmpty() || password.isEmpty()) {
            statusLabel.setText("Please enter username and password.");
            return;
        }

        if (!CryptoUtils.isValidUsername(username)) {
            statusLabel.setText("Invalid username. Use only alphanumeric characters.");
            return;
        }

        String pemFilename = username + ".pem";

        try {
            // Attempt to load and decrypt keys
            statusLabel.setText("Verifying credentials...");
            PrivateKey privateKey = CryptoUtils.loadEncryptedPrivateKey(pemFilename, password);

            // Load public key
            String pubFilename = username + ".pub";
            PublicKey publicKey = null;
            try {
                publicKey = CryptoUtils.loadPublicKey(pubFilename);
            } catch (Exception e) {
                System.err.println("Warning: Public key not found or invalid.");
            }

            // Store in SessionManager
            SessionManager.getInstance().setUsername(username);
            SessionManager.getInstance().setPrivateKey(privateKey);
            if (publicKey != null) {
                SessionManager.getInstance().setPublicKey(publicKey);
            }

            System.out.println("Login successful for user: " + username);
            App.setRoot("primary");
            App.setMaximized(true);

        } catch (Exception e) {
            e.printStackTrace();
            statusLabel.setText("Login failed: " + e.getMessage());
        }
    }

    @FXML
    private void handleRegister(ActionEvent event) {
        String username = usernameField.getText().trim();
        String password = passwordField.getText();

        if (username.isEmpty() || password.isEmpty()) {
            statusLabel.setText("Please enter username and password.");
            return;
        }

        if (!CryptoUtils.isValidUsername(username)) {
            statusLabel.setText("Invalid username. Use only alphanumeric characters.");
            return;
        }

        String pemFilename = username + ".pem";
        String pubFilename = username + ".pub";

        // Check if user already exists
        if (new java.io.File(pemFilename).exists()) {
            statusLabel.setText("User '" + username + "' already exists.");
            return;
        }

        try {
            statusLabel.setText("Generating keys...");
            KeyPair keyPair = CryptoUtils.generateKeyPair();

            statusLabel.setText("Saving encrypted keys...");
            CryptoUtils.saveEncryptedPrivateKey(keyPair.getPrivate(), password, pemFilename);
            CryptoUtils.savePublicKey(keyPair.getPublic(), pubFilename);

            // Store in SessionManager
            SessionManager.getInstance().setUsername(username);
            SessionManager.getInstance().setPrivateKey(keyPair.getPrivate());
            SessionManager.getInstance().setPublicKey(keyPair.getPublic());

            System.out.println("Registration successful for user: " + username);
            App.setRoot("primary");
            App.setMaximized(true);

        } catch (Exception e) {
            e.printStackTrace();
            statusLabel.setText("Registration failed: " + e.getMessage());
        }
    }
}
