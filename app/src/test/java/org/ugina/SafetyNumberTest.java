package org.ugina;

import org.testng.annotations.Test;
import org.ugina.crypto.RsaCrypto;
import org.ugina.crypto.SafetyNumber;

import java.security.KeyPair;

import static org.testng.Assert.*;

public class SafetyNumberTest {

    @Test
    public void bothSidesComputeTheSameNumberRegardlessOfOrder() throws Exception {
        KeyPair alice = RsaCrypto.generateKeyPair();
        KeyPair bob = RsaCrypto.generateKeyPair();

        String fromAlice = SafetyNumber.of("alice", alice.getPublic(),
                "bob", bob.getPublic());
        String fromBob = SafetyNumber.of("bob", bob.getPublic(),
                "alice", alice.getPublic());

        assertEquals(fromAlice, fromBob);
    }

    @Test
    public void numberHasTwelveGroupsOfFiveDigits() throws Exception {
        KeyPair alice = RsaCrypto.generateKeyPair();
        KeyPair bob = RsaCrypto.generateKeyPair();

        String number = SafetyNumber.of("alice", alice.getPublic(),
                "bob", bob.getPublic());

        assertTrue(number.matches("\\d{5}( \\d{5}){11}"), number);
    }

    @Test
    public void replacingOneKeyChangesTheNumber() throws Exception {
        KeyPair alice = RsaCrypto.generateKeyPair();
        KeyPair bob = RsaCrypto.generateKeyPair();
        KeyPair mallory = RsaCrypto.generateKeyPair();

        String real = SafetyNumber.of("alice", alice.getPublic(),
                "bob", bob.getPublic());
        String substituted = SafetyNumber.of("alice", alice.getPublic(),
                "bob", mallory.getPublic());

        assertNotEquals(real, substituted);
    }

    @Test
    public void changingAUsernameChangesTheNumber() throws Exception {
        KeyPair alice = RsaCrypto.generateKeyPair();
        KeyPair bob = RsaCrypto.generateKeyPair();

        String withBob = SafetyNumber.of("alice", alice.getPublic(),
                "bob", bob.getPublic());
        String withCarol = SafetyNumber.of("alice", alice.getPublic(),
                "carol", bob.getPublic());

        assertNotEquals(withBob, withCarol);
    }
}
