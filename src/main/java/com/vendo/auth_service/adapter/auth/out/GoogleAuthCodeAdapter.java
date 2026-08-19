package com.vendo.auth_service.adapter.auth.out;

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.vendo.auth_service.adapter.auth.out.props.GoogleOauthProps;
import com.vendo.auth_service.domain.user.exception.GoogleAuthException;
import com.vendo.auth_service.port.auth.GoogleAuthCodePort;
import com.vendo.core_lib.utils.ObjectUtils;
import com.vendo.core_lib.utils.StringUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class GoogleAuthCodeAdapter implements GoogleAuthCodePort {

    private final GoogleOauthProps props;
    private final NetHttpTransport transport;

    @Override
    public String exchange(String authorizationCode) {
        try {
            GoogleTokenResponse response =
                    new GoogleAuthorizationCodeTokenRequest(
                            transport,
                            GsonFactory.getDefaultInstance(),
                            props.getClientId(),
                            props.getClientSecret(),
                            authorizationCode,
                            props.getRedirectUri()
                    ).execute();

            throwIfNotValidResponse(response);
            return response.getIdToken();

        } catch (Exception e) {
            log.error("Unable to exchange authCode: ", e);
            throw new GoogleAuthException("Google authorization failed.");
        }
    }

    private void throwIfNotValidResponse(GoogleTokenResponse response) {
        if (ObjectUtils.isNull(response) || StringUtils.isEmpty(response.getIdToken())) {
            throw new IllegalStateException("Invalid google oauth response.");
        }

    }


}
