package org.example.client;

public class ClientMessage {
    public String toClientName;
    public String fromClientName;
    public String message;
    public long timestamp;
    public CommandType commandType;

    public ClientMessage() {
    }

    public ClientMessage(String toClientName, String fromClientName, String message, CommandType commandType) {
        this.toClientName = toClientName;
        this.fromClientName = fromClientName;
        this.message = message;
        this.timestamp = System.currentTimeMillis();
        this.commandType = commandType;
    }
}
