package com.vendo.auth_service.port.security;

public interface TokenIdentityPort {

    String extractId(String token);

}
