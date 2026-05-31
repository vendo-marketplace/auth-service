package com.vendo.auth_service.port.auth;

public interface BearerTokenExtractor {

    String extract(String token);

}
