package com.vendo.auth_service.port.auth.usecase;

import com.vendo.auth_service.application.auth.command.AuthCommand;
import com.vendo.auth_service.application.auth.command.CompleteAuthCommand;
import com.vendo.auth_service.application.auth.command.RefreshCommand;
import com.vendo.auth_service.domain.user.model.User;

public interface AuthUseCase {

    void signIn(AuthCommand command);

    void signUp(AuthCommand command);

    void complete(CompleteAuthCommand command);

    void refresh(RefreshCommand command);

    User me();

}
