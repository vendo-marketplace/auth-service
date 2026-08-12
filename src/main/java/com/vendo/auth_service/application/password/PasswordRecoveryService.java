package com.vendo.auth_service.application.password;

import com.vendo.auth_service.adapter.code.out.props.PasswordRecoveryCodeNamespace;
import com.vendo.auth_service.application.auth.command.CodeCommand;
import com.vendo.auth_service.application.auth.dto.UpdateUserRequest;
import com.vendo.auth_service.application.code.CodeSender;
import com.vendo.auth_service.application.code.CodeService;
import com.vendo.auth_service.application.password.command.ResetPasswordCommand;
import com.vendo.auth_service.domain.user.exception.SamePasswordException;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.password.PasswordRecoveryUseCase;
import com.vendo.auth_service.port.security.PasswordHashingPort;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserLookupPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.event_lib.code.CodeEventType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
class PasswordRecoveryService implements PasswordRecoveryUseCase {

    private final PasswordRecoveryCodeNamespace passwordRecoveryCodeNamespace;

    private final UserQueryPort userQueryPort;
    private final UserCommandPort userCommandPort;
    private final UserLookupPort userLookupPort;
    private final PasswordHashingPort passwordHashingPort;

    private final CodeSender codeSender;
    private final CodeService codeService;

    @Override
    public void forgot(String email) {
        userLookupPort.requireExistence(email);
        codeSender.send(new CodeCommand(email, CodeEventType.PASSWORD_RECOVERY), passwordRecoveryCodeNamespace);
    }

    @Override
    public void reset(String code, ResetPasswordCommand command) {
        String email = codeService.peek(code, passwordRecoveryCodeNamespace);
        User user = userQueryPort.getByEmail(email);

        validateNotSamePassword(command.password(), user.password());
        codeService.cleanUp(code, passwordRecoveryCodeNamespace);

        userCommandPort.update(user.id(), UpdateUserRequest.builder()
                .password(passwordHashingPort.hash(command.password()))
                .build());
    }

    @Override
    public void resend(String email) {
        userLookupPort.requireExistence(email);
        codeSender.resend(new CodeCommand(email, CodeEventType.PASSWORD_RECOVERY), passwordRecoveryCodeNamespace);
    }

    private void validateNotSamePassword(String newPassword, String oldHashedPassword) {
        if (passwordHashingPort.matches(newPassword, oldHashedPassword)) {
            throw new SamePasswordException("The new password cannot be the same as the current password.");
        }
    }
}
