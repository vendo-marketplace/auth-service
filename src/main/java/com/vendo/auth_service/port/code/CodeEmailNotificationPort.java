package com.vendo.auth_service.port.code;

import com.vendo.event_lib.code.EmailCodeEvent;

public interface CodeEmailNotificationPort {

    void sendEmailNotification(EmailCodeEvent event);

}
