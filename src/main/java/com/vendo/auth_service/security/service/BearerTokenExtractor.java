package com.vendo.auth_service.security.service;

public interface BearerTokenExtractor {

    String parseBearerToken(String bearerToken);

}
