module p2p_file_transfer {
    requires javafx.controls;
    requires javafx.fxml;

    opens p2p_file_transfer to javafx.fxml;
    exports p2p_file_transfer;
}
