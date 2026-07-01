package org.ugina.client;

import java.security.KeyPair;

/**
 * Result of a successful login: everything needed to connect to chat.
 * Groups the JWT with the loaded key pair so callers get one object
 * instead of relying on side-effect fields.
 */
public record LoginResult(String jwt, String username, KeyPair keyPair) {
}