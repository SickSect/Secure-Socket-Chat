package org.ugina;

import org.testng.annotations.Test;
import org.ugina.client.SessionContext;

import java.security.KeyPair;
import static org.testng.Assert.*;

public class SessionContextTest {

    @Test
    public void freshSessionIsNotExpired() throws Exception {
        // свежая сессия не истекла
        KeyPair dummy = org.ugina.crypto.EcdhCrypto.generateKeyPair();
        SessionContext ctx = new SessionContext("bob", dummy);
        assertFalse(ctx.isExpired(), "только что созданная сессия не должна быть expired");
    }

    @Test
    public void touchUpdatesActivity() throws Exception {
        KeyPair dummy = org.ugina.crypto.EcdhCrypto.generateKeyPair();
        SessionContext ctx = new SessionContext("bob", dummy);
        var before = ctx.getLastActivityAt();
        Thread.sleep(10);
        ctx.touch();
        assertTrue(ctx.getLastActivityAt().isAfter(before),
                "touch должен обновить lastActivityAt");
    }
}