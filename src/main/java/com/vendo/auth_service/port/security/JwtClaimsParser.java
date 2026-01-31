package com.vendo.auth_service.port.security;

public interface JwtClaimsParser {

    String extractEmail(String token);

}
