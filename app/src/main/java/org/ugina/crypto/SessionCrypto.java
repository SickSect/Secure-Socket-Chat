package org.ugina.crypto;

import org.ugina.crypto.exception.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * v3 end-to-end session crypto: per-message forward secrecy via a symmetric
 * chain ratchet plus a DH ratchet for break-in recovery.
 *
 * <p>Compared to v2 (two long-lived directional AES keys) this class provides:</p>
 *
 * <ul>
 *   <li>every message is encrypted with a fresh key derived one-way from a
 *       chain key ({@link #kdfCk}); a leaked message key reveals only that
 *       one message — never the rest of the session;</li>
 *   <li>chain keys rotate through a DH ratchet ({@link #kdfRk}): after a
 *       rotation an attacker who stole this side's state cannot derive the
 *       next round of keys without the peer's fresh private key;</li>
 *   <li>the ratchet public key, the global sequence and the chain index are
 *       all authenticated as GCM AAD, so a relay can neither strip the ratchet
 *       header nor reorder/drop/replay messages;</li>
 *   <li>handshake keys remain bound to the full transcript and both
 *       identities, with explicit key confirmation for each side.</li>
 * </ul>
 *
 * <p>The DH ratchet alternates strictly: a side only rotates after receiving
 * the peer's fresh ratchet key. Both sides therefore apply the same sequence
 * of root-key derivations and converge on identical chains.</p>
 */
public final class SessionCrypto {

    public static final byte VERSION = 3;
    /** Header flag: this message carries a fresh ratchet public key (65 bytes). */
    public static final byte FLAG_NEW_RATCHET_KEY = 0x01;

    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8;
    private static final int LONG_LENGTH = Long.BYTES;
    private static final int RATCHET_PUB_LENGTH = 65;
    /** [version:1][flags:1][sequence:8][chainIndex:8][iv:12] */
    private static final int BASE_HEADER_LENGTH = 1 + 1 + LONG_LENGTH + LONG_LENGTH + IV_LENGTH;
    private static final String INFO_PREFIX = "secure-chat/v3";
    private static final String SIGNING_LABEL = "secure-chat/v3/handshake";
    private static final SecureRandom RANDOM = new SecureRandom();

    private SessionCrypto() {
    }

    /**
     * Values derived once during the handshake. The root key is the shared
     * state of the DH ratchet; confirmation tags prove both sides derived it.
     */
    public record DerivedKeys(
            byte[] rootKey,
            byte[] initiatorConfirm,
            byte[] responderConfirm,
            byte[] transcriptHash
    ) {
    }

    /** One step of the DH ratchet: a new root key plus a fresh chain key. */
    public record RatchetStep(byte[] rootKey, byte[] chainKey) {
    }

    /** One step of the symmetric chain: the message key and the next chain. */
    public record ChainStep(byte[] messageKey, byte[] nextChainKey) {
    }

    /** Parsed v3 message header (ciphertext included, tag verified later). */
    public record Header(
            byte flags,
            byte[] ratchetPublicKey,
            long sequence,
            long chainIndex,
            byte[] iv,
            byte[] cipherText
    ) {
        public boolean hasNewRatchetKey() {
            return (flags & FLAG_NEW_RATCHET_KEY) != 0;
        }
    }

    /**
     * Derive the shared ratchet root key and both confirmation tags from the
     * raw ECDH secret.
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
            byte[] rootKey = HkdfCrypto.derive(
                    sharedSecret, transcriptHash, INFO_PREFIX + "/root", 32);
            byte[] initiatorConfirm = HkdfCrypto.derive(
                    sharedSecret, transcriptHash, INFO_PREFIX + "/initiator-confirm", 32);
            byte[] responderConfirm = HkdfCrypto.derive(
                    sharedSecret, transcriptHash, INFO_PREFIX + "/responder-confirm", 32);

            return new DerivedKeys(rootKey, initiatorConfirm, responderConfirm, transcriptHash);
        } catch (Exception e) {
            throw new CryptoException("Session key derivation failed", e);
        }
    }

    /**
     * DH-ratchet step (RFC-9180-style DHKDF): rekey the root and open a new
     * chain. {@code direction} is the traffic direction the chain will carry
     * ("i2r" or "r2i") — both sides label the same chain identically, which
     * is what makes their root-key sequences converge.
     */
    public static RatchetStep kdfRk(byte[] rootKey, byte[] dhSecret, String direction)
            throws CryptoException {
        if (rootKey == null || dhSecret == null || direction == null) {
            throw new CryptoException("Incomplete ratchet KDF input", null);
        }
        try {
            byte[] pseudoRandomKey = hmac(rootKey, dhSecret);
            byte[] newRoot = hmac(pseudoRandomKey,
                    (INFO_PREFIX + "/ratchet/" + direction + "/root").getBytes(StandardCharsets.UTF_8));
            byte[] chainKey = hmac(pseudoRandomKey,
                    (INFO_PREFIX + "/ratchet/" + direction + "/chain").getBytes(StandardCharsets.UTF_8));
            wipe(pseudoRandomKey);
            return new RatchetStep(newRoot, chainKey);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("Ratchet rekey failed", e);
        }
    }

    /**
     * Symmetric chain step: derive this message's key and advance the chain.
     * Both outputs are one-way functions of the chain key, so knowing a
     * message key (or the next chain) never reveals the previous ones.
     */
    public static ChainStep kdfCk(byte[] chainKey) throws CryptoException {
        if (chainKey == null) {
            throw new CryptoException("Missing chain key", null);
        }
        try {
            byte[] messageKey = hmac(chainKey,
                    (INFO_PREFIX + "/msg-key").getBytes(StandardCharsets.UTF_8));
            byte[] nextChainKey = hmac(chainKey,
                    (INFO_PREFIX + "/next-chain").getBytes(StandardCharsets.UTF_8));
            return new ChainStep(messageKey, nextChainKey);
        } catch (Exception e) {
            throw new CryptoException("Chain derivation failed", e);
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
     * Encrypt one message under a single-use message key.
     *
     * <p>Wire format:
     * {@code [version:1][flags:1][ratchetPub?:65][sequence:8][chainIndex:8][iv:12][ciphertext+tag]}.
     * Everything in the header is authenticated as AAD, so a relay cannot
     * strip the ratchet key, rewrite the sequence, or move the message to
     * another chain without breaking GCM.</p>
     *
     * @param newRatchetPublicKey raw 65-byte ratchet public key to piggyback,
     *                            or {@code null} when the peer already knows it
     */
    public static String encrypt(
            String plainText,
            SecretKey messageKey,
            String sender,
            String recipient,
            long sequence,
            long chainIndex,
            byte[] newRatchetPublicKey
    ) throws CryptoException {
        if (newRatchetPublicKey != null && newRatchetPublicKey.length != RATCHET_PUB_LENGTH) {
            throw new CryptoException("Ratchet public key must be 65 bytes", null);
        }
        try {
            byte flags = newRatchetPublicKey != null ? FLAG_NEW_RATCHET_KEY : 0;
            byte[] iv = new byte[IV_LENGTH];
            RANDOM.nextBytes(iv);

            byte[] aad = aad(flags, newRatchetPublicKey, sender, recipient, sequence, chainIndex);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, messageKey, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            cipher.updateAAD(aad);
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            int headerLength = BASE_HEADER_LENGTH
                    + (newRatchetPublicKey != null ? RATCHET_PUB_LENGTH : 0);
            ByteBuffer payload = ByteBuffer.allocate(headerLength + cipherText.length);
            payload.put(VERSION);
            payload.put(flags);
            if (newRatchetPublicKey != null) {
                payload.put(newRatchetPublicKey);
            }
            payload.putLong(sequence);
            payload.putLong(chainIndex);
            payload.put(iv);
            payload.put(cipherText);

            return Base64.getEncoder().encodeToString(payload.array());
        } catch (Exception e) {
            throw new CryptoException("E2E encryption failed", e);
        }
    }

    /**
     * Parses and structurally validates a v3 payload header. The GCM tag is
     * checked later by {@link #decrypt}; this method exists so the caller can
     * run the ratchet/sequence state machine before touching the ciphertext.
     */
    public static Header parseHeader(String base64Payload) throws CryptoException {
        try {
            byte[] payload = Base64.getDecoder().decode(base64Payload);
            if (payload.length < BASE_HEADER_LENGTH + TAG_LENGTH_BYTES) {
                throw new CryptoException("E2E payload is too short", null);
            }

            ByteBuffer buffer = ByteBuffer.wrap(payload);
            byte version = buffer.get();
            if (version != VERSION) {
                throw new CryptoException("Unsupported E2E payload version: " + version, null);
            }
            byte flags = buffer.get();
            if ((flags & ~FLAG_NEW_RATCHET_KEY) != 0) {
                throw new CryptoException("Unknown E2E header flags: " + flags, null);
            }

            byte[] ratchetPublicKey = null;
            if ((flags & FLAG_NEW_RATCHET_KEY) != 0) {
                if (buffer.remaining() < RATCHET_PUB_LENGTH + LONG_LENGTH * 2 + IV_LENGTH + TAG_LENGTH_BYTES) {
                    throw new CryptoException("E2E payload truncated before ratchet key", null);
                }
                ratchetPublicKey = new byte[RATCHET_PUB_LENGTH];
                buffer.get(ratchetPublicKey);
            }

            long sequence = buffer.getLong();
            long chainIndex = buffer.getLong();
            byte[] iv = new byte[IV_LENGTH];
            buffer.get(iv);
            byte[] cipherText = new byte[buffer.remaining()];
            buffer.get(cipherText);

            return new Header(flags, ratchetPublicKey, sequence, chainIndex, iv, cipherText);
        } catch (CryptoException e) {
            throw e;
        } catch (IllegalArgumentException | java.nio.BufferUnderflowException e) {
            throw new CryptoException("Malformed E2E payload", e);
        }
    }

    /**
     * Decrypt one message with the single-use message key selected by the
     * caller's ratchet state machine and verify it against the expected
     * sequence and chain index. Any mismatch (replay, reordering, dropped
     * message, stripped ratchet flag) fails authentication.
     */
    public static String decrypt(
            String base64Payload,
            SecretKey messageKey,
            String sender,
            String recipient,
            long expectedSequence,
            long expectedChainIndex
    ) throws CryptoException {
        try {
            Header header = parseHeader(base64Payload);
            if (header.sequence() != expectedSequence) {
                throw new CryptoException(
                        "Unexpected E2E sequence: got " + header.sequence()
                                + ", expected " + expectedSequence, null);
            }
            if (header.chainIndex() != expectedChainIndex) {
                throw new CryptoException(
                        "Unexpected E2E chain index: got " + header.chainIndex()
                                + ", expected " + expectedChainIndex, null);
            }

            byte[] aad = aad(header.flags(), header.ratchetPublicKey(),
                    sender, recipient, header.sequence(), header.chainIndex());

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, messageKey,
                    new GCMParameterSpec(TAG_LENGTH_BITS, header.iv()));
            cipher.updateAAD(aad);

            return new String(cipher.doFinal(header.cipherText()), StandardCharsets.UTF_8);
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

    private static byte[] hmac(byte[] key, byte[] message) throws CryptoException {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (Exception e) {
            throw new CryptoException("HMAC-SHA256 failed", e);
        }
    }

    private static byte[] aad(
            byte flags,
            byte[] ratchetPublicKey,
            String sender,
            String recipient,
            long sequence,
            long chainIndex
    ) {
        byte[] senderBytes = sender.getBytes(StandardCharsets.UTF_8);
        byte[] recipientBytes = recipient.getBytes(StandardCharsets.UTF_8);
        int ratchetLength = ratchetPublicKey != null ? ratchetPublicKey.length : 0;
        ByteBuffer aad = ByteBuffer.allocate(
                1 + 1 + 4 + ratchetLength
                        + 4 + senderBytes.length + 4 + recipientBytes.length
                        + 8 + 8);
        aad.put(VERSION);
        aad.put(flags);
        aad.putInt(ratchetLength);
        if (ratchetPublicKey != null) {
            aad.put(ratchetPublicKey);
        }
        putBytes(aad, senderBytes);
        putBytes(aad, recipientBytes);
        aad.putLong(sequence);
        aad.putLong(chainIndex);
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

    private static void wipe(byte[] value) {
        if (value != null) {
            java.util.Arrays.fill(value, (byte) 0);
        }
    }
}
