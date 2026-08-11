package com.vendo.auth_service.application.code;

import com.vendo.auth_service.adapter.code.out.props.CodeNamespace;
import com.vendo.auth_service.application.auth.command.CodeCommand;
import com.vendo.auth_service.domain.code.exception.CodeAlreadySentException;
import com.vendo.auth_service.domain.code.CodePolicyService;
import com.vendo.auth_service.port.code.CodeEmailNotificationPort;
import com.vendo.auth_service.port.code.CodeGenerator;
import com.vendo.auth_service.port.code.CodeStorage;
import com.vendo.auth_service.port.code.StorageValue;
import com.vendo.event_lib.code.EmailCodeEvent;
import com.vendo.redis_lib.exception.CodeExpiredException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class EmailCodeSender implements CodeSender {

    private final CodeStorage codeStorage;
    private final CodeGenerator codeGenerator;
    private final CodeEmailNotificationPort codeEmailNotificationPort;

    @Override
    public void send(CodeCommand command, CodeNamespace namespace) {
        throwIfCodeAlreadySent(command.email(), namespace);
        String code = codeGenerator.generate();
        saveCodeNamespaces(code, command.email(), namespace);
        codeEmailNotificationPort.sendEmailNotification(new EmailCodeEvent(code, command.email(), command.type()));
    }

    @Override
    public void resend(CodeCommand command, CodeNamespace codeNamespace) {
        String code = getCodeOrThrow(command.email(), codeNamespace);
        int attempts = getAttemptsOrThrow(command.email(), codeNamespace);
        codeEmailNotificationPort.sendEmailNotification(new EmailCodeEvent(code, command.email(), command.type()));
        increaseAttempts(attempts, command.email(), codeNamespace);
    }

    private void throwIfCodeAlreadySent(String email, CodeNamespace namespace) {
        boolean activeKey = codeStorage.hasActiveKey(namespace.getEmail().buildPrefix(email));
        if (activeKey) {
            throw new CodeAlreadySentException("Code already sent.");
        }
    }

    private void saveCodeNamespaces(String code, String email, CodeNamespace namespace) {
        Map<String, StorageValue> values = Map.of(
                namespace.getCode().buildPrefix(code), new StorageValue(email, namespace.getCode().ttl()),
                namespace.getEmail().buildPrefix(email), new StorageValue(code, namespace.getEmail().ttl())
        );
        codeStorage.saveValues(values);
    }

    private String getCodeOrThrow(String email, CodeNamespace codeNamespace) {
        return codeStorage.getValue(codeNamespace.getEmail().buildPrefix(email))
                .orElseThrow(() -> new CodeExpiredException("No active code session found."));
    }

    private int getAttemptsOrThrow(String email, CodeNamespace codeNamespace) {
        Optional<String> codeStorageValue = codeStorage.getValue(codeNamespace.getAttempts().buildPrefix(email));
        int attempts = codeStorageValue.map(Integer::parseInt).orElse(0);
        CodePolicyService.throwIfTooManyAttempts(attempts);
        return attempts;
    }

    private void increaseAttempts(int attempts, String email, CodeNamespace codeNamespace) {
        codeStorage.saveValue(
                codeNamespace.getAttempts().buildPrefix(email),
                String.valueOf(++attempts),
                codeNamespace.getAttempts().ttl());
    }

}
