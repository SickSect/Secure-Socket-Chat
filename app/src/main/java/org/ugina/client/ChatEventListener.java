package org.ugina.client;

public interface ChatEventListener {
    void onMessage(String from, String text);
    void onDelivered();
    void onError(String code, String text);
    void onSystem(String text);
    void onConnectionLost();
    void onDecryptionFailed(String from);
}
