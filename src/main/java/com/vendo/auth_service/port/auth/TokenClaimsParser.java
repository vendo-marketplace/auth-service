package com.vendo.auth_service.port.auth;

public interface TokenClaimsParser {

    String extractSubject(String token);

}
