package com.vendo.auth_service.application.auth.command;

import com.vendo.event_lib.code.CodeEventType;

public record CodeCommand(String email, CodeEventType type) {
}
