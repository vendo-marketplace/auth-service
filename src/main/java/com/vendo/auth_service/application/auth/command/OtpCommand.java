package com.vendo.auth_service.application.auth.command;

import com.vendo.event_lib.OtpEventType;

public record OtpCommand(String email, OtpEventType type) {
}
