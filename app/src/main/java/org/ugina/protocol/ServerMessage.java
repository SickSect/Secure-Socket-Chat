package org.ugina.protocol;

public class ServerMessage {
    public MessageType type;
    public String fromClientName;    // для DM
    public String e2ePayload;        // для DM (зашифрованный пакет)
    public String text;              // для SYSTEM, ERROR
    public ErrorCode errorCode;      // для ERROR
    public String username;          // для PUBLIC_KEY (чей ключ)
    public String publicKey;         // для PUBLIC_KEY (Base64)
}
