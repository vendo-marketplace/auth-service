package com.vendo.auth_service.adapter.security.out;

import com.vendo.auth_service.adapter.security.out.jwt.props.JwtProperties;
import com.vendo.auth_service.application.auth.dto.TokenPayload;
import com.vendo.auth_service.port.security.AuthCookieApplierPort;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthCookieApplierAdapter implements AuthCookieApplierPort {

    private final HttpServletResponse response;
    private final JwtProperties jwtProperties;

    private static final String LAX_REDIRECT_STRATEGY_PREFIX = "Lax";
    private static final String ALL_PATHS = "/", REFRESH_PATH = "/auth/refresh";
    private static final String ACCESS_PREFIX = "accessToken", REFRESH_PREFIX = "refreshToken";

    @Override
    public void apply(TokenPayload payload) {
        JwtProperties.Secret secret = jwtProperties.getSecret();

        ResponseCookie accessCookie = ResponseCookie
                .from(ACCESS_PREFIX, payload.accessToken())
                .httpOnly(true)
                .secure(true)
                .sameSite(LAX_REDIRECT_STRATEGY_PREFIX)
                .path(ALL_PATHS)
                .maxAge(secret.accessExpirationTime())
                .build();

        ResponseCookie refreshCookie = ResponseCookie
                .from(REFRESH_PREFIX, payload.refreshToken())
                .httpOnly(true)
                .secure(true)
                .sameSite(LAX_REDIRECT_STRATEGY_PREFIX)
                .path(REFRESH_PATH)
                .maxAge(secret.refreshExpirationTime())
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
    }

}
