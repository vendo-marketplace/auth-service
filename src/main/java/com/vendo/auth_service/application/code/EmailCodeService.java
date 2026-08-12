package com.vendo.auth_service.application.code;

import com.vendo.auth_service.adapter.code.out.props.CodeNamespace;
import com.vendo.auth_service.port.code.CodeStorage;
import com.vendo.redis_lib.exception.CodeExpiredException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
class EmailCodeService implements CodeService {

    private final CodeStorage codeStorage;

    @Override
    public String consume(String code, CodeNamespace namespace) {
        String email = getEmailByCodeOrThrow(code, namespace);
        cleanUpCodeNamespaces(code, email, namespace);
        return email;
    }

    @Override
    public String peek(String code, CodeNamespace namespace) {
        return getEmailByCodeOrThrow(code, namespace);
    }

    @Override
    public void cleanUp(String code, CodeNamespace namespace) {
        String email = getEmailByCodeOrThrow(code, namespace);
        cleanUpCodeNamespaces(code, email, namespace);
    }

    private void cleanUpCodeNamespaces(String code, String email, CodeNamespace namespace) {
        codeStorage.deleteValues(
                namespace.getCode().buildPrefix(code),
                namespace.getEmail().buildPrefix(email),
                namespace.getAttempts().buildPrefix(email)
        );
    }

    private String getEmailByCodeOrThrow(String code, CodeNamespace namespace) {
        return codeStorage.getValue(namespace.getCode().buildPrefix(code))
                .orElseThrow(() -> new CodeExpiredException("Code session expired."));
    }

}
