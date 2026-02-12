package com.vendo.auth_service.domain.auth.dto;

public class AuthRequestDataBuilder {

    public static AuthRequest.AuthRequestBuilder buildUserWithAllFields() {
        return AuthRequest.builder()
                .email("test@gmail.com")
                .password("Qwerty1234@");
    }

}
