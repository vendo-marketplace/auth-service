package com.vendo.auth_service.port.security;

public interface BearerTokenExtractor {

    String parse(String token);

}
