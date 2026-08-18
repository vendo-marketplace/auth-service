package com.vendo.auth_service.adapter.auth.out;

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.vendo.auth_service.domain.user.exception.GoogleAuthException;
import com.vendo.auth_service.port.auth.GoogleAuthCodePort;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.GeneralSecurityException;

@Component
@RequiredArgsConstructor
public class GoogleAuthCodeAdapter implements GoogleAuthCodePort {

    @Value("${google.oauth.client-id}")
    private String clientId;

    @Value("${google.oauth.client-secret}")
    private String clientSecret;

    @Value("${google.oauth.redirect-uri}")
    private String redirectUri;

    @Override
    public String exchange(String authorizationCode) {
        try {
            GoogleTokenResponse response =
                    new GoogleAuthorizationCodeTokenRequest(
                            GoogleNetHttpTransport.newTrustedTransport(),
                            GsonFactory.getDefaultInstance(),
                            clientId,
                            clientSecret,
                            authorizationCode,
                            redirectUri
                    ).execute();

            return response.getIdToken();

        } catch (IOException | GeneralSecurityException e) {
            throw new GoogleAuthException("Failed to exchange Google authorization code.");
        }
    }

}
