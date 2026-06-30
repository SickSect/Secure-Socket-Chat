package org.ugina.client;

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * SecretKey implementation that actually wipes its key material on destroy().
 * <p>
 * Java's built-in SecretKeySpec does NOT clear key bytes (JDK-6263419) — its
 * destroy() throws and the raw bytes linger in memory until GC. This class owns
 * its own byte array and zeroes it on destroy(), giving best-effort key wiping.
 * <p>
 * Limitation: the JVM may still copy the object during GC compaction, leaving
 * stale copies. Full memory wiping is impossible in pure Java; this reduces, not
 * eliminates, exposure in a memory dump.
 */
public final class DestroyableSecretKey implements SecretKey, Destroyable {

    private final byte[] key;
    private final String algorithm;
    private volatile boolean destroyed = false;

    public DestroyableSecretKey(byte[] key, String algorithm) {
        // Own copy — caller may wipe their array independently
        this.key = Arrays.copyOf(key, key.length);
        this.algorithm = algorithm;
    }

    @Override
    public String getAlgorithm() {
        checkNotDestroyed();
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        checkNotDestroyed();
        // Return a copy so callers can't reach (or wipe) our internal array
        return Arrays.copyOf(key, key.length);
    }

    @Override
    public void destroy() {
        if (!destroyed) {
            Arrays.fill(key, (byte) 0);
            destroyed = true;
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("Key has been destroyed");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SecretKey)) return false;
        SecretKey other = (SecretKey) o;
        if (!algorithm.equalsIgnoreCase(other.getAlgorithm())) return false;
        // Constant-time compare to avoid timing leaks
        if (this.destroyed) return false;
        return MessageDigest.isEqual(this.getEncoded(), other.getEncoded());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(key) * 31 + algorithm.toLowerCase().hashCode();
    }
}