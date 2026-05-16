package org.ugina.protocol;

public class ClientMessage {
    public CommandType commandType;
    public String username;          // для JOIN
    public String publicKey;         // для JOIN (Base64)
    public String toClientName;      // для SEND_MESSAGE, GET_KEY
    public String e2ePayload;        // для SEND_MESSAGE (Base64)
    public Long timestamp;           // для SEND_MESSAGE
    public String nonce;             // для SEND_MESSAGE (Base64)

    public ClientMessage() {}
}
