package com.vendo.auth_service.application.auth;

import com.vendo.auth_service.application.auth.command.AuthCommand;
import com.vendo.auth_service.application.auth.command.CompleteAuthCommand;
import com.vendo.auth_service.application.auth.command.RefreshCommand;
import com.vendo.auth_service.application.auth.dto.*;
import com.vendo.auth_service.domain.user.exception.IncorrectPasswordException;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.auth.AuthUserPort;
import com.vendo.auth_service.port.auth.usecase.AuthUseCase;
import com.vendo.auth_service.port.security.AuthCookieApplierPort;
import com.vendo.auth_service.port.security.PasswordHashingPort;
import com.vendo.auth_service.port.security.TokenIdentityPort;
import com.vendo.auth_service.port.security.TokenGenerationPort;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
class AuthService implements AuthUseCase {

    private final UserQueryPort userQueryPort;
    private final UserCommandPort userCommandPort;

    private final TokenGenerationPort tokenGenerationPort;
    private final PasswordHashingPort passwordHashingPort;
    private final TokenIdentityPort tokenIdentityPort;

    private final AuthUserPort authUserPort;
    private final AuthCookieApplierPort cookieApplierPort;

    @Override
    public void signIn(AuthCommand command) {
        User user = userQueryPort.getByEmail(command.email());

        boolean matches = passwordHashingPort.matches(command.password(), user.password());
        if (!matches) throw new IncorrectPasswordException("Wrong credentials.");

        TokenPayload tokenPayload = tokenGenerationPort.generate(user);
        cookieApplierPort.apply(tokenPayload);
    }

    @Override
    public void signUp(AuthCommand command) {
        String hashedPassword = passwordHashingPort.hash(command.password());
        User user = userCommandPort.save(SaveUserRequest.builder()
                .email(command.email())
                .status(UserStatus.ACTIVE)
                .roles(Set.of(UserRole.USER))
                .providerType(ProviderType.LOCAL)
                .password(hashedPassword)
                .build());

        TokenPayload tokenPayload = tokenGenerationPort.generate(user);
        cookieApplierPort.apply(tokenPayload);
    }

    @Override
    public void complete(CompleteAuthCommand command) {
        User user = userQueryPort.getById(authUserPort.getAuthUser().id());
        user.throwIfEmailNotVerified();
        user.throwIfCompleted();
        userCommandPort.update(user.id(), UpdateUserRequest.builder().fullName(command.fullName()).build());
    }

    @Override
    public void refresh(RefreshCommand command) {
        User user = userQueryPort.getById(tokenIdentityPort.extractId(command.refreshToken()));
        TokenPayload tokenPayload = tokenGenerationPort.generate(user);
        cookieApplierPort.apply(tokenPayload);
    }

    @Override
    public User me() {
        return userQueryPort.getById(authUserPort.getAuthUser().id());
    }
}
