package com.vendo.auth_service.adapter.out.security.service;

import com.vendo.auth_service.port.security.PasswordHashingPort;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PasswordEncoderAdapter implements PasswordHashingPort {

    private final PasswordEncoder passwordEncoder;

    @Override
    public String hash(String raw) {
        return passwordEncoder.encode(raw);
    }

    @Override
    public boolean matches(String raw, String hash) {
        return passwordEncoder.matches(raw, hash);
    }
}
