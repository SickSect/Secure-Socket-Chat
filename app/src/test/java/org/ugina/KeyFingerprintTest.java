package org.ugina;

import org.testng.annotations.Test;
import org.ugina.crypto.KeyFingerprint;
import org.ugina.crypto.RsaCrypto;

import java.security.KeyPair;

import static org.testng.Assert.*;

public class KeyFingerprintTest {

    @Test
    public void fingerprintIsStableForTheSameKey() throws Exception {
        KeyPair pair = RsaCrypto.generateKeyPair();
        String first = KeyFingerprint.hex(pair.getPublic());
        String second = KeyFingerprint.hex(pair.getPublic());

        assertEquals(first, second);
        assertEquals(first.length(), 64);
        assertTrue(first.matches("[0-9a-f]{64}"));
    }

    @Test
    public void differentKeysProduceDifferentFingerprints() throws Exception {
        KeyPair first = RsaCrypto.generateKeyPair();
        KeyPair second = RsaCrypto.generateKeyPair();

        assertNotEquals(
                KeyFingerprint.hex(first.getPublic()),
                KeyFingerprint.hex(second.getPublic()));
    }

    @Test
    public void formattingIsReadableAndNormalizationAcceptsPastedValues() {
        String raw = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
                + "a1b2c3d4e5f60718293a4b5c6d7e8f90";

        String formatted = KeyFingerprint.format(raw);
        assertEquals(formatted, "a1b2 c3d4 e5f6 0718 293a 4b5c 6d7e 8f90 "
                + "a1b2 c3d4 e5f6 0718 293a 4b5c 6d7e 8f90");
        assertEquals(KeyFingerprint.normalize(formatted), raw);
        assertEquals(KeyFingerprint.normalize("A1:B2-C3 D4"), "a1b2c3d4");
    }

    @Test
    public void prefixMustBeLongEnoughAndMatch() {
        String raw = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
                + "a1b2c3d4e5f60718293a4b5c6d7e8f90";

        assertTrue(KeyFingerprint.matchesPrefix(raw, "a1b2c3d4e5f60718"));
        assertTrue(KeyFingerprint.matchesPrefix(raw, "a1b2 c3d4 e5f6 0718"));
        assertFalse(KeyFingerprint.matchesPrefix(raw, "a1b2c3d4"));
        assertFalse(KeyFingerprint.matchesPrefix(raw, "ffffffffffffffff"));
    }

    @Test
    public void shortFormUsesSixteenCharacters() throws Exception {
        KeyPair pair = RsaCrypto.generateKeyPair();
        String full = KeyFingerprint.hex(pair.getPublic());

        assertEquals(KeyFingerprint.shortForm(full), full.substring(0, 16));
    }
}
