package com.vendo.auth_service.port.otp;

import com.vendo.event_lib.EmailOtpEvent;

public interface OtpEmailNotificationPort {

    void sendOtpEmailNotification(EmailOtpEvent emailOtpEvent);

}
