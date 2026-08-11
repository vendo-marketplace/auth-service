package com.vendo.auth_service.domain.code;

import com.vendo.auth_service.domain.code.exception.TooManyCodeRequestsException;

public class CodePolicyService {

    public static void throwIfTooManyAttempts(int attempt) {
        if (attempt >= 3) {
            throw new TooManyCodeRequestsException("Reached maximum attempts.");
        }
    }

}