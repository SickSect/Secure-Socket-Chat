package org.ugina.auth;

public record AuthToken(
        String value,
        long expiresAt){

}