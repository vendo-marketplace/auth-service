package com.vendo.auth_service.port.security;

public interface JwtClaimsParser {

    String parseEmailFromToken(String jwtToken);

}
