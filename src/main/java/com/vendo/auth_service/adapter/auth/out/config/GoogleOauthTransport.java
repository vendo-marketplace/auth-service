package com.vendo.auth_service.adapter.auth.out.config;

import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.vendo.auth_service.domain.user.exception.GoogleAuthException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.security.GeneralSecurityException;

@Slf4j
@Configuration
public class GoogleOauthTransport {

    @Bean
    public NetHttpTransport googleNetHttpTransport() {
        try {
            return GoogleNetHttpTransport.newTrustedTransport();
        } catch (GeneralSecurityException | IOException e) {
            log.error("Unable to instantiate google net http transport: ", e);
            throw new GoogleAuthException("Google authorization failed.");
        }
    }

}
