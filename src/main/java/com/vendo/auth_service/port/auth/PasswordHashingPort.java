package com.vendo.auth_service.port.auth;

public interface PasswordHashingPort {

    String hash(String raw);
    boolean matches(String raw, String hash);

}
