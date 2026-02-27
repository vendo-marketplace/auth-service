package com.vendo.auth_service.application.otp;

import com.vendo.auth_service.adapter.otp.out.props.OtpNamespace;
import com.vendo.auth_service.application.auth.command.OtpCommand;

public interface OtpService {

    void sendOtp(OtpCommand command, OtpNamespace namespace);

    void resendOtp(OtpCommand command, OtpNamespace otpNamespace);

}
