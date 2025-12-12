package p2p_file_transfer;

public class CommandProcessor {

    private PrimaryController controller;

    public CommandProcessor(PrimaryController controller) {
        this.controller = controller;
    }

    public boolean execute(String input) {
        String command = input.trim().toLowerCase();

        // File
        if (command.equals("/send file")) {
            controller.openFileChooser();
            return true;
        }

        // Clear
        if (command.equals("/clear") || command.equals("/cls")) {
            controller.clearChat();
            return true;
        }

        // Check IP
        if (command.equals("/myip")) {
            return true;
        }

        // Help
        if (command.equals("/help")) {
            String helpMsg = "List of commands:\n" +
                    "  /send file : Open file selection\n" +
                    "  /clear     : Clear chat screen\n" +
                    "  /help      : Show this help message";
            controller.showSystemMessage(helpMsg);
            return true;
        }

        // Command not found
        if (command.startsWith("/")) {
            controller.showSystemMessage("Command not found. Type /help to see help message.");
            return true;
        }

        // Normal message
        return false;
    }
}