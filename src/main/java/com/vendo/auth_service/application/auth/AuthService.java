package com.vendo.auth_service.application.auth;

import com.vendo.auth_service.application.auth.command.AuthCommand;
import com.vendo.auth_service.application.auth.command.CompleteAuthCommand;
import com.vendo.auth_service.application.auth.dto.*;
import com.vendo.auth_service.domain.user.exception.IncorrectPasswordException;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.auth.AuthUserPort;
import com.vendo.auth_service.port.auth.usecase.AuthUseCase;
import com.vendo.auth_service.port.security.*;
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
    private final TokenIdentityPort tokenIdentityPort;
    private final PasswordHashingPort passwordHashingPort;

    private final AuthUserPort authUserPort;
    private final AuthCookieApplierPort cookieApplierPort;
    private final AuthCookieRetrieverPort cookieRetrieverPort;

    @Override
    public void signIn(AuthCommand command) {
        var user = userQueryPort.getByEmail(command.email());

        boolean matches = passwordHashingPort.matches(command.password(), user.password());
        if (!matches) throw new IncorrectPasswordException("Wrong credentials.");

        applyAuth(user);
    }

    @Override
    public void signUp(AuthCommand command) {
        String hashedPassword = passwordHashingPort.hash(command.password());
        var saved = userCommandPort.save(SaveUserRequest.builder()
                .email(command.email())
                .status(UserStatus.ACTIVE)
                .roles(Set.of(UserRole.USER))
                .providerType(ProviderType.LOCAL)
                .password(hashedPassword)
                .build());

        applyAuth(saved);
    }

    @Override
    public void logOut() {
        cookieApplierPort.expire();
    }

    @Override
    public void complete(CompleteAuthCommand command) {
        var user = userQueryPort.getById(authUserPort.getAuthUser().id());

        user.throwIfEmailNotVerified();
        user.throwIfCompleted();

        var updated =  userCommandPort.update(user.id(), UpdateUserRequest.builder().fullName(User.normalizeFullName(command.fullName())).build());

        applyAuth(updated);
    }

    @Override
    public void refresh() {
        var user = userQueryPort.getById(tokenIdentityPort.extractId(cookieRetrieverPort.retrieveRefresh()));
        applyAuth(user);
    }

    @Override
    public User me() {
        return userQueryPort.getById(authUserPort.getAuthUser().id());
    }

    private void applyAuth(User user) {
        TokenPayload tokenPayload = tokenGenerationPort.generate(user);
        cookieApplierPort.apply(tokenPayload);
    }
}
