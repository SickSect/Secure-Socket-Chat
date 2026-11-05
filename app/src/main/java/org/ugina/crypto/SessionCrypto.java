package org.ugina.crypto;

import org.ugina.crypto.exception.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * v2 end-to-end session crypto.
 *
 * <p>Compared to the old scheme (one AES key, constant HKDF info, no transcript
 * binding, no replay protection) this class provides:</p>
 *
 * <ul>
 *   <li>keys bound to the full handshake transcript (both identities and both
 *       ephemeral public keys), so a frame cannot be replayed against another
 *       peer or another session;</li>
 *   <li>separate keys for each direction (initiator→responder,
 *       responder→initiator);</li>
 *   <li>an explicit key-confirmation value for both sides;</li>
 *   <li>a monotonic per-session sequence number embedded in the payload and
 *       authenticated as GCM AAD, which makes message replay/reordering by a
 *       malicious relay detectable.</li>
 * </ul>
 */
public final class SessionCrypto {

    public static final byte VERSION = 2;

    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8;
    private static final int SEQUENCE_LENGTH = Long.BYTES;
    private static final int HEADER_LENGTH = 1 + SEQUENCE_LENGTH + IV_LENGTH;
    private static final String INFO_PREFIX = "secure-chat/v2";
    private static final String SIGNING_LABEL = "secure-chat/v2/handshake";
    private static final SecureRandom RANDOM = new SecureRandom();

    private SessionCrypto() {
    }

    /**
     * Directional keys and confirmation values derived from one ECDH secret.
     * The record deliberately exposes raw confirmation bytes, but keys are
     * wrapped in {@link DestroyableSecretKey} so callers can wipe them.
     */
    public record DerivedKeys(
            SecretKey initiatorToResponder,
            SecretKey responderToInitiator,
            byte[] initiatorConfirm,
            byte[] responderConfirm,
            byte[] transcriptHash
    ) {
    }

    /**
     * Derive directional session keys from the raw ECDH secret.
     *
     * @param sharedSecret          raw ECDH output (same on both sides)
     * @param initiator             username of the client that sent INIT_SESSION
     * @param responder             username of the client that answered with SESSION_ACK
     * @param initiatorEphemeralPub encoded initiator ephemeral public key
     * @param responderEphemeralPub encoded responder ephemeral public key
     */
    public static DerivedKeys derive(
            byte[] sharedSecret,
            String initiator,
            String responder,
            byte[] initiatorEphemeralPub,
            byte[] responderEphemeralPub
    ) throws CryptoException {
        byte[] transcriptHash = transcriptHash(
                initiator, responder, initiatorEphemeralPub, responderEphemeralPub);

        try {
            byte[] i2r = HkdfCrypto.derive(
                    sharedSecret, transcriptHash, INFO_PREFIX + "/i2r", 32);
            byte[] r2i = HkdfCrypto.derive(
                    sharedSecret, transcriptHash, INFO_PREFIX + "/r2i", 32);
            byte[] initiatorConfirm = HkdfCrypto.derive(
                    sharedSecret, transcriptHash, INFO_PREFIX + "/initiator-confirm", 32);
            byte[] responderConfirm = HkdfCrypto.derive(
                    sharedSecret, transcriptHash, INFO_PREFIX + "/responder-confirm", 32);

            return new DerivedKeys(
                    new DestroyableSecretKey(i2r, "AES"),
                    new DestroyableSecretKey(r2i, "AES"),
                    initiatorConfirm,
                    responderConfirm,
                    transcriptHash
            );
        } catch (Exception e) {
            throw new CryptoException("Session key derivation failed", e);
        }
    }

    /**
     * SHA-256 over a canonical, length-prefixed encoding of the handshake
     * transcript. Both sides must build it in the same order (initiator first).
     */
    public static byte[] transcriptHash(
            String initiator,
            String responder,
            byte[] initiatorEphemeralPub,
            byte[] responderEphemeralPub
    ) throws CryptoException {
        if (initiator == null || responder == null
                || initiatorEphemeralPub == null || responderEphemeralPub == null) {
            throw new CryptoException("Incomplete handshake transcript", null);
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            updateLengthPrefixed(digest, (INFO_PREFIX + "/transcript").getBytes(StandardCharsets.UTF_8));
            updateLengthPrefixed(digest, initiator.getBytes(StandardCharsets.UTF_8));
            updateLengthPrefixed(digest, responder.getBytes(StandardCharsets.UTF_8));
            updateLengthPrefixed(digest, initiatorEphemeralPub);
            updateLengthPrefixed(digest, responderEphemeralPub);
            return digest.digest();
        } catch (Exception e) {
            throw new CryptoException("Transcript hashing failed", e);
        }
    }

    /**
     * Data covered by the long-term RSA signature during the handshake.
     * Binding the role and both identities prevents a captured INIT_SESSION
     * from being replayed against a different peer.
     */
    public static byte[] signingPayload(
            String role,
            String signer,
            String peer,
            byte[] ephemeralPublicKey
    ) {
        ByteBuffer buffer = ByteBuffer.allocate(
                4 + SIGNING_LABEL.length()
                        + 4 + role.length()
                        + 4 + signer.length()
                        + 4 + peer.length()
                        + 4 + ephemeralPublicKey.length);
        putString(buffer, SIGNING_LABEL);
        putString(buffer, role);
        putString(buffer, signer);
        putString(buffer, peer);
        buffer.putInt(ephemeralPublicKey.length);
        buffer.put(ephemeralPublicKey);
        return buffer.array();
    }

    /**
     * Encrypt one message with a directional session key.
     *
     * <p>The wire format is {@code [version:1][sequence:8][iv:12][ciphertext+tag]}.
     * The sequence number and both usernames are authenticated as AAD; the relay
     * can read them but cannot modify them without breaking GCM.</p>
     */
    public static String encrypt(
            String plainText,
            SecretKey key,
            String sender,
            String recipient,
            long sequence
    ) throws CryptoException {
        try {
            byte[] iv = new byte[IV_LENGTH];
            RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            cipher.updateAAD(aad(sender, recipient, sequence));

            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            ByteBuffer payload = ByteBuffer.allocate(HEADER_LENGTH + cipherText.length);
            payload.put(VERSION);
            payload.putLong(sequence);
            payload.put(iv);
            payload.put(cipherText);

            return Base64.getEncoder().encodeToString(payload.array());
        } catch (Exception e) {
            throw new CryptoException("E2E encryption failed", e);
        }
    }

    /**
     * Decrypt one message and verify that it has the exact sequence number we
     * expect. This rejects replays, reordering and dropped-message gaps.
     */
    public static String decrypt(
            String base64Payload,
            SecretKey key,
            String sender,
            String recipient,
            long expectedSequence
    ) throws CryptoException {
        try {
            byte[] payload = Base64.getDecoder().decode(base64Payload);
            if (payload.length < HEADER_LENGTH + TAG_LENGTH_BYTES) {
                throw new CryptoException("E2E payload is too short", null);
            }

            ByteBuffer buffer = ByteBuffer.wrap(payload);
            byte version = buffer.get();
            if (version != VERSION) {
                throw new CryptoException("Unsupported E2E payload version: " + version, null);
            }
            long sequence = buffer.getLong();
            if (sequence != expectedSequence) {
                throw new CryptoException(
                        "Unexpected E2E sequence: got " + sequence
                                + ", expected " + expectedSequence, null);
            }

            byte[] iv = new byte[IV_LENGTH];
            buffer.get(iv);
            byte[] cipherText = new byte[buffer.remaining()];
            buffer.get(cipherText);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            cipher.updateAAD(aad(sender, recipient, sequence));

            return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("E2E decryption failed", e);
        }
    }

    public static boolean constantTimeEquals(byte[] expected, byte[] actual) {
        if (expected == null || actual == null) return false;
        return MessageDigest.isEqual(expected, actual);
    }

    private static byte[] aad(String sender, String recipient, long sequence) {
        byte[] senderBytes = sender.getBytes(StandardCharsets.UTF_8);
        byte[] recipientBytes = recipient.getBytes(StandardCharsets.UTF_8);
        ByteBuffer aad = ByteBuffer.allocate(
                1 + 4 + senderBytes.length + 4 + recipientBytes.length + 8);
        aad.put(VERSION);
        putBytes(aad, senderBytes);
        putBytes(aad, recipientBytes);
        aad.putLong(sequence);
        return aad.array();
    }

    private static void updateLengthPrefixed(MessageDigest digest, byte[] value) {
        digest.update(ByteBuffer.allocate(4).putInt(value.length).array());
        digest.update(value);
    }

    private static void putString(ByteBuffer buffer, String value) {
        putBytes(buffer, value.getBytes(StandardCharsets.UTF_8));
    }

    private static void putBytes(ByteBuffer buffer, byte[] value) {
        buffer.putInt(value.length);
        buffer.put(value);
    }
}
