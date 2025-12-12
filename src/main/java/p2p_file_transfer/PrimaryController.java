package p2p_file_transfer;

import java.io.File;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import p2p_file_transfer.manager.SessionManager;
import p2p_file_transfer.model.PeerInfo;
import p2p_file_transfer.network.ClientNode;
import p2p_file_transfer.network.PeerDiscoveryService;
import p2p_file_transfer.network.ServerListener;
import p2p_file_transfer.network.ServerNode;
import p2p_file_transfer.util.CryptoUtils;
import p2p_file_transfer.util.NetworkUtil;

public class PrimaryController implements Initializable, ServerListener {

    // --- GUI Components matching updated FXML ---
    @FXML
    private Label lblCpu;
    @FXML
    private Label lblRam;
    @FXML
    private Label lblNetwork;
    @FXML
    private Label lblUser;

    @FXML
    private VBox chatPanel;
    @FXML
    private VBox peerPanel;
    @FXML
    private javafx.scene.layout.AnchorPane playground;
    @FXML
    private VBox chatPanelBody;
    @FXML
    private VBox peerPanelBody;
    @FXML
    private Button btnCollapseChat;
    @FXML
    private Button btnCollapsePeers;

    @FXML
    private TextArea txtChatArea;
    @FXML
    private TextField txtPeerID;
    @FXML
    private TextField txtMessage;
    @FXML
    private Button btnSend;
    @FXML
    private ListView<String> peerListView;

    // --- Logic & Network ---
    private ServerNode serverNode;
    private ClientNode clientNode;
    private PeerDiscoveryService discoveryService;
    private static final int PORT = 9999;
    private File selectedFile;
    private Map<String, PeerInfo> cachedPeers = new HashMap<>(); // PeerID -> PeerInfo

    // --- Dragging Variables ---
    private double xOffset = 0;
    private double yOffset = 0;

    // --- Collapse State ---
    private double chatPanelExpandedHeight = 400;
    private double peerPanelExpandedHeight = 300;

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        String username = SessionManager.getInstance().getUsername();
        String myIp = NetworkUtil.getMyIP();

        // Generate Peer ID from public key
        String myPeerID = "UNKNOWN";
        if (SessionManager.getInstance().getPublicKey() != null) {
            myPeerID = CryptoUtils.generatePeerID(SessionManager.getInstance().getPublicKey());
        }

        clientNode = new ClientNode();
        serverNode = new ServerNode(PORT, this);
        new Thread(serverNode).start();

        discoveryService = new PeerDiscoveryService(
                username != null ? username : "Guest",
                PORT,
                myIp,
                myPeerID);
        discoveryService.startListener();

        lblUser.setText((username != null ? username : "Guest") + " | ID: " + myPeerID);

        appendLog("My Peer ID: " + myPeerID);
        appendLog("My IP: " + myIp + ":" + PORT);
        appendLog("--------------------------------\n");

        makeDraggable(chatPanel);
        makeDraggable(peerPanel);

        peerListView.setOnMouseClicked(event -> handlePeerClick());

        startSystemStatsThread();
    }

    private void makeDraggable(Node node) {
        node.setOnMousePressed(event -> {
            node.toFront();
            xOffset = event.getSceneX() - node.getLayoutX();
            yOffset = event.getSceneY() - node.getLayoutY();
        });
        node.setOnMouseDragged(event -> {
            double newX = event.getSceneX() - xOffset;
            double newY = event.getSceneY() - yOffset;

            double playgroundWidth = playground.getWidth();
            double playgroundHeight = playground.getHeight();
            double nodeWidth = node.getBoundsInLocal().getWidth();
            double nodeHeight = node.getBoundsInLocal().getHeight();

            newX = Math.max(0, Math.min(newX, playgroundWidth - nodeWidth));
            newY = Math.max(0, Math.min(newY, playgroundHeight - nodeHeight));

            node.setLayoutX(newX);
            node.setLayoutY(newY);
        });
    }

    // --- Sidebar Actions ---

    @FXML
    private void toggleChat(ActionEvent event) {
        boolean isVisible = chatPanel.isVisible();
        chatPanel.setVisible(!isVisible);
        if (!isVisible) {
            chatPanel.toFront(); // Bring to front when opening
        }
    }

    @FXML
    private void togglePeers(ActionEvent event) {
        boolean isVisible = peerPanel.isVisible();
        peerPanel.setVisible(!isVisible);
        if (!isVisible) {
            peerPanel.toFront();
        }
    }

    @FXML
    private void toggleCollapseChat(ActionEvent event) {
        boolean isVisible = chatPanelBody.isVisible();
        chatPanelBody.setVisible(!isVisible);
        chatPanelBody.setManaged(!isVisible);
        btnCollapseChat.setText(isVisible ? "+" : "−");

        if (isVisible) {
            chatPanelExpandedHeight = chatPanel.getHeight();
            chatPanel.setPrefHeight(javafx.scene.layout.Region.USE_COMPUTED_SIZE);
            chatPanel.setMinHeight(javafx.scene.layout.Region.USE_COMPUTED_SIZE);
            chatPanel.setMaxHeight(javafx.scene.layout.Region.USE_COMPUTED_SIZE);
        } else {
            chatPanel.setPrefHeight(chatPanelExpandedHeight);
            chatPanel.setMinHeight(javafx.scene.layout.Region.USE_COMPUTED_SIZE);
            chatPanel.setMaxHeight(javafx.scene.layout.Region.USE_PREF_SIZE);
        }
    }

    @FXML
    private void toggleCollapsePeers(ActionEvent event) {
        boolean isVisible = peerPanelBody.isVisible();
        peerPanelBody.setVisible(!isVisible);
        peerPanelBody.setManaged(!isVisible);
        btnCollapsePeers.setText(isVisible ? "+" : "−");

        if (isVisible) {
            peerPanelExpandedHeight = peerPanel.getHeight();
            peerPanel.setPrefHeight(javafx.scene.layout.Region.USE_COMPUTED_SIZE);
            peerPanel.setMinHeight(javafx.scene.layout.Region.USE_COMPUTED_SIZE);
            peerPanel.setMaxHeight(javafx.scene.layout.Region.USE_COMPUTED_SIZE);
        } else {
            peerPanel.setPrefHeight(peerPanelExpandedHeight);
            peerPanel.setMinHeight(javafx.scene.layout.Region.USE_COMPUTED_SIZE);
            peerPanel.setMaxHeight(javafx.scene.layout.Region.USE_PREF_SIZE);
        }
    }

    @FXML
    private void handleLogout(ActionEvent event) {
        SessionManager.getInstance().clearSession();
        stopServer();
        System.out.println("User logged out.");
        try {
            App.setRoot("login");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // --- Core Chat Logic ---

    @FXML
    private void sendMessage(ActionEvent event) {
        String targetPeerID = txtPeerID.getText().trim().toUpperCase();
        String message = txtMessage.getText().trim();

        if (targetPeerID.isEmpty()) {
            appendLog("[System]: Please enter Peer ID!");
            return;
        }

        // Resolve Peer ID to IP
        PeerInfo targetPeer = cachedPeers.get(targetPeerID);
        if (targetPeer == null) {
            appendLog("[System]: Peer ID '" + targetPeerID + "' not found. Click Refresh in Peers panel first.");
            return;
        }

        String targetIp = targetPeer.getIp();
        int targetPort = targetPeer.getPort();

        try {
            if (this.selectedFile != null) {
                clientNode.sendFile(targetIp, targetPort, this.selectedFile);
                appendLog("Me → [" + targetPeerID + "]: [Sending File] " + this.selectedFile.getName());
                this.selectedFile = null;
                txtMessage.setEditable(true);
                txtMessage.setStyle("");
                txtMessage.clear();
            } else {
                if (message.isEmpty())
                    return;

                clientNode.sendText(targetIp, targetPort, message);
                appendLog("Me → [" + targetPeerID + "]: " + message);
                txtMessage.clear();
            }
        } catch (Exception e) {
            appendLog("[Error]: Can't send. " + e.getMessage());
        }
    }

    @Override
    public void onMessageReceived(String message) {
        Platform.runLater(() -> {
            appendLog("Friend: " + message);
        });
    }

    private void appendLog(String log) {
        txtChatArea.appendText(log + "\n");
    }

    public void stopServer() {
        if (serverNode != null) {
            serverNode.stop();
        }
        if (discoveryService != null) {
            discoveryService.stopListener();
        }
    }

    @FXML
    private void refreshPeers() {
        peerListView.getItems().clear();
        peerListView.getItems().add("Scanning...");

        discoveryService.discoverPeers(peers -> {
            Platform.runLater(() -> {
                peerListView.getItems().clear();
                cachedPeers.clear();

                if (peers.isEmpty()) {
                    peerListView.getItems().add("No peers found");
                } else {
                    for (PeerInfo peer : peers) {
                        cachedPeers.put(peer.getPeerID(), peer);
                        peerListView.getItems().add(peer.toString());
                    }
                }
            });
        });
    }

    private void handlePeerClick() {
        String selected = peerListView.getSelectionModel().getSelectedItem();
        if (selected == null || selected.equals("Scanning...") || selected.equals("No peers found")) {
            return;
        }
        // Extract Peer ID from format: "username [PEER_ID] (IP)"
        int start = selected.indexOf("[");
        int end = selected.indexOf("]");
        if (start != -1 && end != -1) {
            String peerID = selected.substring(start + 1, end);
            txtPeerID.setText(peerID);
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
            txtMessage.setStyle("-fx-background-color: #e0f7fa; -fx-text-fill: black;");
            appendLog(">> System: Selected file '" + file.getName() + "'.");
        } else {
            txtMessage.clear();
        }
    }

    // --- Mock System Stats ---
    private void startSystemStatsThread() {
        Thread textUpdate = new Thread(() -> {
            while (true) {
                try {
                    // Mock data
                    double cpuLoad = Math.random() * 20 + 5; // 5-25%
                    long ramUsage = (long) (Math.random() * 200 + 400); // 400-600MB
                    int netSpeed = (int) (Math.random() * 50); // 0-50 KB/s

                    Platform.runLater(() -> {
                        lblCpu.setText(String.format("CPU: %.1f%%", cpuLoad));
                        lblRam.setText(String.format("RAM: %dMB", ramUsage));
                        lblNetwork.setText(String.format("Net: %d KB/s", netSpeed));
                    });

                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
        textUpdate.setDaemon(true);
        textUpdate.start();
    }
}
