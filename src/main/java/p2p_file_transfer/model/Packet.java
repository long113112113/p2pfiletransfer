package p2p_file_transfer.model;

public class Packet {
    public static final int TYPE_HELLO = 1;
    public static final int TYPE_FILE = 2;

    // Authentic
    public static final int TYPE_AUTH_REQUEST = 10;
    public static final int TYPE_AUTH_CHALLENGE = 11;
    public static final int TYPE_AUTH_RESPONSE = 12;
    public static final int TYPE_AUTH_RESULT = 13;
}
