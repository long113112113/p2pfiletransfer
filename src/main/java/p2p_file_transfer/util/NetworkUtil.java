package p2p_file_transfer.util;

import java.net.InetAddress;

public class NetworkUtil {
    public static String getMyIP() {
        try {
            return InetAddress.getLocalHost().getHostAddress();
        } catch (Exception e) {
            e.printStackTrace();
            return "127.0.0.1";
        }
    }
}
