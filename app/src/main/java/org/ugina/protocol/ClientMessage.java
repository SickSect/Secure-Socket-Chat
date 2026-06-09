package org.ugina.protocol;

import org.ugina.crypto.RsaCrypto;

import java.security.PublicKey;

public class ClientMessage {
    public CommandType commandType;
    public String username;          // для JOIN
    public String publicKey;         // для JOIN (Base64)
    public String toClientName;      // для SEND_MESSAGE, GET_KEY
    public String e2ePayload;        // для SEND_MESSAGE (Base64)
    public Long timestamp;           // для SEND_MESSAGE
    public String nonce;             // для SEND_MESSAGE (Base64)
    public String ephemeralPublicKey;
    public String signature;

    public ClientMessage() {
    }

    public static ClientMessage join(String clientName, PublicKey publicKey) {
        return new Builder()
                .commandType(CommandType.JOIN)
                .username(clientName)
                .publicKey(RsaCrypto.publicKeyToBase64(publicKey))
                .build();
    }

    public static ClientMessage quit(){
        return new ClientMessage.Builder().commandType(CommandType.QUIT).build();
    }

    public static ClientMessage getKey(String recipient){
        return new Builder().commandType(CommandType.GET_KEY).toClientName(recipient).build();
    }

    public static ClientMessage message(String recipient, String nonce, String e2ePayload){
        return new Builder()
                .commandType(CommandType.SEND_MESSAGE)
                .toClientName(recipient)
                .nonce(nonce)
                .e2ePayload(e2ePayload)
                .timestamp(System.currentTimeMillis())
                .build();
    }

    public static ClientMessage initSession(String toName, String ephemeralPubBase64, String signatureBase64) {
        return new Builder()
                .commandType(CommandType.INIT_SESSION)
                .toClientName(toName)
                .ephemeralPublicKey(ephemeralPubBase64)
                .signature(signatureBase64)
                .build();
    }

    public static ClientMessage sessionAck(String toName, String ephemeralPubBase64, String signatureBase64) {
        return new Builder()
                .commandType(CommandType.SESSION_ACK)
                .toClientName(toName)
                .ephemeralPublicKey(ephemeralPubBase64)
                .signature(signatureBase64)
                .build();
    }

    public ClientMessage(Builder builder) {
        this.commandType = builder.commandType;
        this.username = builder.username;
        this.publicKey = builder.publicKey;
        this.toClientName = builder.toClientName;
        this.e2ePayload = builder.e2ePayload;
        this.timestamp = builder.timestamp;
        this.nonce = builder.nonce;
        this.signature = builder.signature;
        this.ephemeralPublicKey = builder.ephemeralPublicKey;
    }


    public static class Builder {
        public CommandType commandType;
        public String username;          // для JOIN
        public String publicKey;         // для JOIN (Base64)
        public String toClientName;      // для SEND_MESSAGE, GET_KEY
        public String e2ePayload;        // для SEND_MESSAGE (Base64)
        public Long timestamp;           // для SEND_MESSAGE
        public String nonce;             // для SEND_MESSAGE (Base64)
        public String ephemeralPublicKey;
        public String signature;


        public ClientMessage build() {
            return new ClientMessage(this);
        }

        public Builder commandType(CommandType commandType) {
            this.commandType = commandType;
            return this;
        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public Builder publicKey(String publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public Builder toClientName(String toClientName) {
            this.toClientName = toClientName;
            return this;
        }

        public Builder e2ePayload(String e2ePayload) {
            this.e2ePayload = e2ePayload;
            return this;
        }

        public Builder timestamp(Long timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public Builder ephemeralPublicKey(String ephemeralPublicKey) {
            this.ephemeralPublicKey = ephemeralPublicKey;
            return this;

        }

        public Builder signature(String signature) {
            this.signature = signature;
            return this;
        }
    }
}
