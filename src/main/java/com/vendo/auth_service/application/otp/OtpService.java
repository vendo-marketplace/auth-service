package com.vendo.auth_service.application.otp;

import com.vendo.auth_service.adapter.otp.out.props.OtpNamespace;

public interface OtpService {

    String consume(String otp, OtpNamespace namespace);

    String peek(String otp, OtpNamespace namespace);

    void cleanUp(String otp, OtpNamespace namespace);

}