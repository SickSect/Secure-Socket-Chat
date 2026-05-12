package org.ugina.protocol;

public class ClientMessage {
    public CommandType commandType;
    public String clientName;         // для JOIN
    public String toClientName;     // для SEND_MESSAGE
    public String message;          // для SEND_MESSAGE

    public ClientMessage() {}
}
