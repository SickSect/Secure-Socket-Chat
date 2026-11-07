package org.ugina.client;

public interface ChatEventListener {
    void onMessage(String from, String text);
    void onDelivered();
    void onError(String code, String text);
    void onSystem(String text);
    void onConnectionLost();
    void onDecryptionFailed(String from);

    /**
     * Called when a peer key is seen for the first time or explicitly trusted
     * after a change. Default methods keep older listeners source-compatible.
     */
    default void onPeerKeyTrusted(String username, String fingerprint, boolean firstContact) {
    }

    /** Called when the server offers a key that differs from the local pin. */
    default void onPeerKeyChanged(String username,
                                  String expectedFingerprint,
                                  String actualFingerprint) {
    }
}
