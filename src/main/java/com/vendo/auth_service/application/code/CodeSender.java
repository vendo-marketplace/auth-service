package com.vendo.auth_service.application.code;

import com.vendo.auth_service.adapter.code.out.props.CodeNamespace;
import com.vendo.auth_service.application.auth.command.CodeCommand;

public interface CodeSender {

    void send(CodeCommand command, CodeNamespace namespace);

    void resend(CodeCommand command, CodeNamespace codeNamespace);

}
