package com.vendo.auth_service.domain.auth.dto;

import com.vendo.auth_service.adapter.auth.in.dto.CompleteAuthRequest;

public class CompleteAuthRequestDataBuilder {

    public static CompleteAuthRequest.CompleteAuthRequestBuilder withAllFields() {
        return CompleteAuthRequest.builder()
                .fullName("Test Name");
    }

}
