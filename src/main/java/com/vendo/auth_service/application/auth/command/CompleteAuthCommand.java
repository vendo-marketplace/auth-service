package com.vendo.auth_service.application.auth.command;

import java.time.LocalDate;

public record CompleteAuthCommand(String fullName, LocalDate birthDate) {
}
