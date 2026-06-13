package org.ugina.auth;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.ugina.auth.exceptions.AuthenticationException;
import org.ugina.auth.exceptions.InvalidTokenException;
import org.ugina.auth.exceptions.RegistrationException;

@Service
@ConditionalOnProperty(name = "auth.provider", havingValue = "local", matchIfMissing = true)
public class LocalAuthProvider implements AuthProvider {

    @Override
    public UserPrincipal register(String username, String password, String publicKey)
            throws RegistrationException {
        throw new UnsupportedOperationException(
                "register() not implemented yet — will be added in Step 8");
    }

    @Override
    public AuthToken authenticate(String username, String password)
            throws AuthenticationException {
        throw new UnsupportedOperationException(
                "authenticate() not implemented yet — will be added in Step 12");
    }

    @Override
    public UserPrincipal validate(String token) throws InvalidTokenException {
        throw new UnsupportedOperationException(
                "validate() not implemented yet — will be added in Step 14");
    }
}
