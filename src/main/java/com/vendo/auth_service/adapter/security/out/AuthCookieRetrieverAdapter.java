package com.vendo.auth_service.adapter.security.out;

import com.vendo.auth_service.port.security.AuthCookieRetrieverPort;
import com.vendo.core_lib.utils.StringUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Arrays;

import static com.vendo.security_lib.http.HttpUtils.*;

@Component
@RequiredArgsConstructor
public class AuthCookieRetrieverAdapter implements AuthCookieRetrieverPort {

    private final HttpServletRequest request;

    @Override
    public String retrieveAccess() {
        String cookie = extractCookie(request, ACCESS_PREFIX);
        if (StringUtils.isEmpty(cookie)) {
            throw new IllegalArgumentException("Access cookie is not present.");
        }

        return cookie;
    }

    @Override
    public String retrieveRefresh() {
        String cookie = extractCookie(request, REFRESH_PREFIX);
        if (StringUtils.isEmpty(cookie)) {
            throw new IllegalArgumentException("Refresh cookie is not present.");
        }

        return cookie;
    }

    private String extractCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) {
            return null;
        }

        return Arrays.stream(request.getCookies())
                .filter(cookie -> name.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }

}
