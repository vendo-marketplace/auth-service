package com.vendo.auth_service.port.otp;

import com.vendo.integration.kafka.event.EmailOtpEvent;

public interface OtpEmailNotificationPort {

    void sendOtpEmailNotification(EmailOtpEvent emailOtpEvent);

}
