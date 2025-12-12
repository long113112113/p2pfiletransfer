package p2p_file_transfer;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import p2p_file_transfer.util.CryptoUtils;

import java.security.KeyPair;

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

        String pemFilename = username + ".pem";

        try {
            // Attempt to load and decrypt keys
            statusLabel.setText("Verifying credentials...");
            CryptoUtils.loadEncryptedPrivateKey(pemFilename, password);

            // If successful, we can optionally load the public key too, or derive it if
            // needed,
            // but for now just proceeding implies 'Login Successful'.
            // In a real app, you might want to store the keys in a UserSession object.

            System.out.println("Login successful for user: " + username);
            App.setRoot("primary");

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

            System.out.println("Registration successful for user: " + username);
            App.setRoot("primary");

        } catch (Exception e) {
            e.printStackTrace();
            statusLabel.setText("Registration failed: " + e.getMessage());
        }
    }
}
