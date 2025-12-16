package p2p_file_transfer.util;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class CryptoUtilsTest {

    @Test
    public void testIsValidUsername() {
        // Valid usernames
        assertTrue(CryptoUtils.isValidUsername("user1"));
        assertTrue(CryptoUtils.isValidUsername("valid_user"));
        assertTrue(CryptoUtils.isValidUsername("User_123"));

        // Invalid usernames (Path Traversal attempts)
        assertFalse(CryptoUtils.isValidUsername("../etc/passwd"));
        assertFalse(CryptoUtils.isValidUsername("user/name"));
        assertFalse(CryptoUtils.isValidUsername("user\\name"));
        assertFalse(CryptoUtils.isValidUsername(".."));

        // Invalid characters
        assertFalse(CryptoUtils.isValidUsername("user@name"));
        assertFalse(CryptoUtils.isValidUsername("user name"));

        // Empty or null
        assertFalse(CryptoUtils.isValidUsername(""));
        assertFalse(CryptoUtils.isValidUsername(null));
    }
}
