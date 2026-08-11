package com.vendo.auth_service.adapter.code.out;

import com.vendo.auth_service.port.code.CodeGenerator;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;

@Component
class CodeSixDigitGenerator implements CodeGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public String generate() {
        int code = 100000 + RANDOM.nextInt(900000);
        return String.valueOf(code);
    }

}
