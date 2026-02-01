package com.vendo.auth_service.domain.auth.dto;

import com.vendo.auth_service.domain.security.CompleteAuthRequest;

import java.time.LocalDate;

public class CompleteAuthRequestDataBuilder {

    public static CompleteAuthRequest.CompleteAuthRequestBuilder buildCompleteAuthRequestWithAllFields() {
        return CompleteAuthRequest.builder()
                .fullName("Test Name")
                .birthDate(LocalDate.of(2000, 1, 1));
    }

}
