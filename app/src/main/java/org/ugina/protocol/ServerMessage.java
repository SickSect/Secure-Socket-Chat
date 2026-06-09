package org.ugina.protocol;

public class ServerMessage {
    public MessageType type;
    public String fromClientName;
    public String e2ePayload;
    public String text;
    public ErrorCode errorCode;
    public String username;
    public String publicKey;
    public String ephemeralPublicKey;
    public String signature;

    public ServerMessage() {}

    public static ServerMessage dm(String from, String e2ePayload) {
        ServerMessage m = new ServerMessage();
        m.type = MessageType.DM;
        m.fromClientName = from;
        m.e2ePayload = e2ePayload;
        return m;
    }

    public static ServerMessage delivered() {
        ServerMessage m = new ServerMessage();
        m.type = MessageType.DELIVERED;
        return m;
    }

    public static ServerMessage error(ErrorCode code, String text) {
        ServerMessage m = new ServerMessage();
        m.type = MessageType.ERROR;
        m.errorCode = code;
        m.text = text;
        return m;
    }

    public static ServerMessage system(String text) {
        ServerMessage m = new ServerMessage();
        m.type = MessageType.SYSTEM;
        m.text = text;
        return m;
    }

    public static ServerMessage publicKey(String username, String publicKeyBase64) {
        ServerMessage m = new ServerMessage();
        m.type = MessageType.PUBLIC_KEY;
        m.username = username;
        m.publicKey = publicKeyBase64;
        return m;
    }

    public static ServerMessage initSession(String from, String ephemeralPublicKey, String signature){
        ServerMessage m = new ServerMessage();
        m.type = MessageType.INIT_SESSION;
        m.fromClientName = from;
        m.ephemeralPublicKey = ephemeralPublicKey;
        m.signature = signature;
        return m;
    }

    public static ServerMessage sessionAsk(String from, String ephemeralPublicKey, String signature){
        ServerMessage m = new ServerMessage();
        m.type = MessageType.SESSION_ACK;
        m.fromClientName = from;
        m.ephemeralPublicKey = ephemeralPublicKey;
        m.signature = signature;
        return m;
    }
}