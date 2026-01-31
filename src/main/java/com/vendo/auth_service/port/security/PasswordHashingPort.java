package com.vendo.auth_service.port.security;

public interface PasswordHashingPort {

    String hash(String raw);
    boolean matches(String raw, String hash);

}
