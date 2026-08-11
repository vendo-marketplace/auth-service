package com.vendo.auth_service.application.auth;

import com.vendo.auth_service.adapter.code.out.props.EmailVerificationCodeNamespace;
import com.vendo.auth_service.application.auth.command.CodeCommand;
import com.vendo.auth_service.application.auth.dto.UpdateUserRequest;
import com.vendo.auth_service.application.code.CodeSender;
import com.vendo.auth_service.application.code.CodeService;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.auth.usecase.EmailVerificationUseCase;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.event_lib.code.CodeEventType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
class EmailVerificationService implements EmailVerificationUseCase {

    private final UserQueryPort userQueryPort;
    private final UserCommandPort userCommandPort;

    private final CodeService codeService;
    private final CodeSender codeSender;
    private final EmailVerificationCodeNamespace emailVerificationCodeNamespace;

    @Override
    public void send(String email) {
        User user = userQueryPort.getByEmail(email);
        user.throwIfVerified();
        codeSender.send(new CodeCommand(email, CodeEventType.EMAIL_VERIFICATION), emailVerificationCodeNamespace);
    }

    @Override
    public void resend(String email) {
        User user = userQueryPort.getByEmail(email);
        user.throwIfVerified();
        codeSender.resend(new CodeCommand(email, CodeEventType.EMAIL_VERIFICATION), emailVerificationCodeNamespace);
    }

    @Override
    public void validate(String code) {
        String email = codeService.consume(code, emailVerificationCodeNamespace);
        User user = userQueryPort.getByEmail(email);
        user.throwIfVerified();
        userCommandPort.update(user.id(), UpdateUserRequest.builder()
                .emailVerified(true)
                .build());
    }

}
