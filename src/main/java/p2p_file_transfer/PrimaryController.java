package p2p_file_transfer;

import java.io.File;
import java.net.URL;
import java.util.ResourceBundle;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import p2p_file_transfer.network.ClientNode;
import p2p_file_transfer.network.ServerListener;
import p2p_file_transfer.network.ServerNode;
import p2p_file_transfer.util.NetworkUtil;

public class PrimaryController implements Initializable, ServerListener {

    @FXML
    private TextArea txtChatArea;

    @FXML
    private TextField txtIpAddress;

    @FXML
    private TextField txtMessage;

    @FXML
    private Button btnSend;

    private ServerNode serverNode;
    private ClientNode clientNode;
    private static final int PORT = 9999;
    private CommandProcessor commandProcessor;
    private File selectedFile;

    @FXML
    public void initialize(URL url, ResourceBundle rb) {
        clientNode = new ClientNode();
        commandProcessor = new CommandProcessor(this);
        serverNode = new ServerNode(PORT, this);
        new Thread(serverNode).start();

        String myIp = NetworkUtil.getMyIP();
        appendLog("=== P2P CHAT SYSTEM STARTED ===");
        appendLog("My IP Address: " + myIp);
        appendLog("Listening on Port: " + PORT);
        appendLog("--------------------------------\n");
    }

    @FXML
    private void sendMessage(ActionEvent event) {
        String targetIp = txtIpAddress.getText().trim();
        String message = txtMessage.getText().trim();

        if (targetIp.isEmpty()) {
            appendLog("[System]: Pls enter receiver IP!");
            return;
        }

        try {
            if (this.selectedFile != null) {
                // Logic gửi file
                clientNode.sendFile(targetIp, PORT, this.selectedFile);
                appendLog("Me: [Sending File] " + this.selectedFile.getName());

                // Reset sau khi gửi
                this.selectedFile = null;
                txtMessage.setEditable(true);
                txtMessage.setStyle(""); // Reset style
                txtMessage.clear();
            } else {
                // Logic gửi text bình thường
                if (message.isEmpty()) {
                    return;
                }
                if (commandProcessor.execute(message)) {
                    txtMessage.clear();
                    return;
                }

                clientNode.sendText(targetIp, PORT, message);
                appendLog("Me: " + message);
                txtMessage.clear();
            }
        } catch (Exception e) {
            appendLog("[Error]: Cant send. " + e.getMessage());
        }
    }

    @Override
    public void onMessageReceived(String message) {
        Platform.runLater(() -> {
            appendLog("Friend [" + txtIpAddress.getText() + "]: " + message);
        });
    }

    private void appendLog(String log) {
        txtChatArea.appendText(log + "\n");
    }

    public void stopServer() {
        if (serverNode != null) {
            serverNode.stop();
        }
    }

    public void openFileChooser() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select file");

        Stage stage = (Stage) txtChatArea.getScene().getWindow();

        File file = fileChooser.showOpenDialog(stage);

        if (file != null) {
            this.selectedFile = file;

            txtMessage.setText("[Ready to send]: " + file.getName());
            txtMessage.setEditable(false);

            txtMessage.setStyle("-fx-background-color: #e0f7fa;");

            appendLog(">> System: Selected file '" + file.getName() + "'.");
        } else {
            txtMessage.clear();
        }
    }

    public void clearChat() {
        txtChatArea.clear();
        txtMessage.clear();
    }

    public void showSystemMessage(String msg) {
        appendLog("[System]: " + msg);
    }
}
