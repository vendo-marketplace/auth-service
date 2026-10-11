package com.vendo.auth_service.port.code;

import com.vendo.event_lib.code.CodeEmailEvent;

public interface CodeEmailNotificationPort {

    void sendEmailNotification(CodeEmailEvent event);

}
