package com.vendo.auth_service.port.security;

public interface TokenClaimsParser {

    String extractSubject(String token);

}
