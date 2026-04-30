package com.vendo.auth_service.port.otp;

import com.vendo.event_lib.otp.EmailOtpEvent;

public interface OtpEmailNotificationPort {

    void sendOtpEmailNotification(EmailOtpEvent emailOtpEvent);

}
