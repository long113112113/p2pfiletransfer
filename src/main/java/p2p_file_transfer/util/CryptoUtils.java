package p2p_file_transfer.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoUtils {

    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_BIT_LENGTH = 128;
    private static final int IV_SIZE = 12;
    private static final int SALT_SIZE = 16;
    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int AES_KEY_SIZE = 256;

    private static final String PRIVATE_KEY_HEADER = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    private static final String PRIVATE_KEY_FOOTER = "-----END ENCRYPTED PRIVATE KEY-----";
    private static final String PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----";

    /**
     * Generates a new RSA 2048-bit KeyPair.
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    /**
     * Encrypts the Private Key with the password and saves it to a PEM file.
     * Format of Blob before Base64: [Salt (16)][IV (12)][Encrypted Private Key]
     */
    public static void saveEncryptedPrivateKey(PrivateKey privateKey, String password, String filename)
            throws Exception {
        // 1. Generate Salt and IV
        byte[] salt = new byte[SALT_SIZE];
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        random.nextBytes(iv);

        // 2. Derive Key from Password
        SecretKey secretKey = deriveKey(password, salt);

        // 3. Encrypt
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_BIT_LENGTH, iv));
        byte[] encryptedBytes = cipher.doFinal(privateKey.getEncoded());

        // 4. Combine: Salt + IV + CipherText
        ByteBuffer buffer = ByteBuffer.allocate(SALT_SIZE + IV_SIZE + encryptedBytes.length);
        buffer.put(salt);
        buffer.put(iv);
        buffer.put(encryptedBytes);
        byte[] finalBlob = buffer.array();

        // 5. Encode Base64 and wrap in PEM
        String base64Encoded = Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(finalBlob);
        StringBuilder pemContent = new StringBuilder();
        pemContent.append(PRIVATE_KEY_HEADER).append("\n");
        pemContent.append(base64Encoded).append("\n");
        pemContent.append(PRIVATE_KEY_FOOTER);

        // 6. Write to file
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(pemContent.toString().getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * Loads and decrypts the Private Key from a PEM file using the password.
     */
    public static PrivateKey loadEncryptedPrivateKey(String filename, String password) throws Exception {
        // 1. Read File
        File file = new File(filename);
        if (!file.exists()) {
            throw new IOException("Key file not found: " + filename);
        }
        String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);

        // 2. Strip Headers/Footers and Decode Base64
        String base64Content = content
                .replace(PRIVATE_KEY_HEADER, "")
                .replace(PRIVATE_KEY_FOOTER, "")
                .replaceAll("\\s", ""); // Remove newlines/spaces

        byte[] blob = Base64.getDecoder().decode(base64Content);

        // 3. Extract Salt, IV, CipherText
        if (blob.length < SALT_SIZE + IV_SIZE) {
            throw new GeneralSecurityException("Invalid key file format.");
        }

        ByteBuffer buffer = ByteBuffer.wrap(blob);
        byte[] salt = new byte[SALT_SIZE];
        byte[] iv = new byte[IV_SIZE];
        buffer.get(salt);
        buffer.get(iv);

        byte[] encryptedBytes = new byte[buffer.remaining()];
        buffer.get(encryptedBytes);

        // 4. Derive Key
        SecretKey secretKey = deriveKey(password, salt);

        // 5. Decrypt
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_BIT_LENGTH, iv));
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // 6. Reconstruct PrivateKey
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decryptedBytes));
    }

    /**
     * Saves the Public Key to a standard PEM file.
     */
    public static void savePublicKey(PublicKey publicKey, String filename) throws IOException {
        String base64Encoded = Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(publicKey.getEncoded());
        StringBuilder pemContent = new StringBuilder();
        pemContent.append(PUBLIC_KEY_HEADER).append("\n");
        pemContent.append(base64Encoded).append("\n");
        pemContent.append(PUBLIC_KEY_FOOTER);

        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(pemContent.toString().getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * Loads Public Key from a PEM file
     */
    public static PublicKey loadPublicKey(String filename) throws Exception {
        File file = new File(filename);
        if (!file.exists()) {
            throw new IOException("Public Key file not found: " + filename);
        }
        String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        String base64Content = content
                .replace(PUBLIC_KEY_HEADER, "")
                .replace(PUBLIC_KEY_FOOTER, "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(base64Content);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
    }

    /**
     * Generates a short Peer ID from a PublicKey using SHA-256 hash.
     * Returns first 8 characters of the hex-encoded hash in uppercase.
     */
    public static String generatePeerID(PublicKey publicKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(publicKey.getEncoded());
            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < 4; i++) { // Only first 4 bytes = 8 hex chars
                String hex = Integer.toHexString(0xff & hash[i]);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString().toUpperCase();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return "UNKNOWN";
        }
    }

    private static SecretKey deriveKey(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, AES_KEY_SIZE);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    // ==================== DIGITAL SIGNATURE METHODS ====================

    /**
     * Signs a message using RSA private key with SHA256.
     * 
     * @param message    the message to sign
     * @param privateKey the RSA private key
     * @return Base64-encoded signature string
     * @throws Exception if signing fails
     */
    public static String sign(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    /**
     * Verifies a signature using RSA public key.
     * 
     * @param message      the original message
     * @param signatureStr Base64-encoded signature
     * @param publicKey    the RSA public key
     * @return true if signature is valid, false otherwise
     */
    public static boolean verify(String message, String signatureStr, PublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(message.getBytes(StandardCharsets.UTF_8));
            return signature.verify(Base64.getDecoder().decode(signatureStr));
        } catch (Exception e) {
            System.err.println("[Security] Signature verification failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Encodes a PublicKey to Base64 string for network transmission.
     * 
     * @param publicKey the RSA public key
     * @return Base64-encoded string representation
     */
    public static String encodePublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * Decodes a Base64 string back to PublicKey.
     * 
     * @param encoded Base64-encoded public key string
     * @return the decoded PublicKey, or null if decoding fails
     */
    public static PublicKey decodePublicKey(String encoded) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(encoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (Exception e) {
            System.err.println("[Security] Failed to decode public key: " + e.getMessage());
            return null;
        }
    }

    /**
     * Verifies that a PeerID matches the hash of the given PublicKey.
     * This ensures cryptographic binding between PeerID and PublicKey.
     * 
     * @param peerID    the claimed peer ID
     * @param publicKey the public key to verify against
     * @return true if peerID == hash(publicKey), false otherwise
     */
    public static boolean verifyPeerIdentity(String peerID, PublicKey publicKey) {
        if (peerID == null || publicKey == null) {
            return false;
        }
        String expectedPeerID = generatePeerID(publicKey);
        return peerID.equals(expectedPeerID);
    }

    /**
     * Validates that the username contains only alphanumeric characters and underscores.
     * This prevents path traversal vulnerabilities when using the username in file paths.
     *
     * @param username the username to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidUsername(String username) {
        return username != null && username.matches("^[a-zA-Z0-9_]+$");
    }
}
