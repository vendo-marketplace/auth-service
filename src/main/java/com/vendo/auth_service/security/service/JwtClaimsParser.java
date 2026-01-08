package com.vendo.auth_service.security.service;

public interface JwtClaimsParser {

    String parseEmailFromToken(String jwtToken);

}
