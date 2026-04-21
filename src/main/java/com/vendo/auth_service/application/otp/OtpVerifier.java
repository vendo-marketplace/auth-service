package com.vendo.auth_service.application.otp;

import com.vendo.auth_service.adapter.otp.out.props.OtpNamespace;

public interface OtpVerifier {

    String verify(String otp, OtpNamespace namespace);

}
