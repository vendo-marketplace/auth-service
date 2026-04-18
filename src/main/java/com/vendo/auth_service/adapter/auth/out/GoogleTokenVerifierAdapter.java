package com.vendo.auth_service.adapter.auth.out;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.vendo.auth_service.adapter.auth.in.exception.GoogleAuthException;
import com.vendo.auth_service.application.auth.dto.GoogleTokenPayload;
import com.vendo.auth_service.port.auth.GoogleTokenVerifierPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.GeneralSecurityException;

@Slf4j
@Component
@RequiredArgsConstructor
public class GoogleTokenVerifierAdapter implements GoogleTokenVerifierPort {

    private final GoogleIdTokenVerifier googleIdTokenVerifier;

    private static final String PAYLOAD_FULL_NAME_FIELD = "name";

    @Override
    public GoogleTokenPayload verify(String idToken) {
        try {
            GoogleIdToken googleIdToken = googleIdTokenVerifier.verify(idToken);

            if (googleIdToken == null) {
                throw new GoogleAuthException("Id token is not verified.");
            }

            GoogleIdToken.Payload payload = googleIdToken.getPayload();
            return GoogleTokenPayload.builder()
                    .email(payload.getEmail())
                    .fullName((String) payload.get(PAYLOAD_FULL_NAME_FIELD))
                    .build();
        } catch (GeneralSecurityException | IOException e) {
            log.error("Google Id token security check failed: {}", e.getMessage());
            throw new GoogleAuthException("Invalid Id token.");
        }
    }

}
