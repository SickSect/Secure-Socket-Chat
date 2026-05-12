package org.ugina.protocol;

public class ServerMessage {
    public MessageType type;
    public String fromClientName;
    public String text;
    public ErrorCode errorCode;
}
