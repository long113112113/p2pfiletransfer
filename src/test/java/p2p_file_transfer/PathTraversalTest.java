package p2p_file_transfer;

import org.junit.jupiter.api.Test;
import p2p_file_transfer.util.CryptoUtils;
import static org.junit.jupiter.api.Assertions.*;

public class PathTraversalTest {

    @Test
    public void testUsernameValidation() {
        // Malicious username should be rejected
        String maliciousUsername = "../../etc/passwd";
        assertFalse(CryptoUtils.isValidUsername(maliciousUsername), "Malicious username should be invalid");

        // Valid usernames should be accepted
        assertTrue(CryptoUtils.isValidUsername("validUser"), "Valid username should be accepted");
        assertTrue(CryptoUtils.isValidUsername("user_123"), "Alphanumeric with underscore should be accepted");

        // Edge cases
        assertFalse(CryptoUtils.isValidUsername("user.name"), "Dot should not be allowed");
        assertFalse(CryptoUtils.isValidUsername("user/name"), "Slash should not be allowed");
        assertFalse(CryptoUtils.isValidUsername(""), "Empty username should be valid regex wise? No, + means 1 or more");
        // Actually, ^[a-zA-Z0-9_]+$ means at least one character.
        // Let's verify empty string
        assertFalse(CryptoUtils.isValidUsername(""), "Empty username should be invalid");
    }
}
