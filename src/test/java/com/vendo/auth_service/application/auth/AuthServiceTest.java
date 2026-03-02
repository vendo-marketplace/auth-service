package com.vendo.auth_service.application.auth;

import com.vendo.auth_service.adapter.security.out.jwt.parser.JwtClaimsParser;
import com.vendo.auth_service.application.auth.command.AuthCommand;
import com.vendo.auth_service.application.auth.command.CompleteAuthCommand;
import com.vendo.auth_service.application.auth.command.RefreshCommand;
import com.vendo.auth_service.application.auth.dto.AuthResponse;
import com.vendo.auth_service.application.auth.dto.TokenPayload;
import com.vendo.auth_service.domain.auth.dto.TokenPayloadDataBuilder;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.security.BearerTokenExtractor;
import com.vendo.auth_service.port.security.PasswordHashingPort;
import com.vendo.auth_service.port.security.TokenGenerationService;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.security_lib.exception.InvalidTokenException;
import com.vendo.user_lib.exception.UserAlreadyExistsException;
import com.vendo.user_lib.exception.UserBlockedException;
import com.vendo.user_lib.exception.UserNotFoundException;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDate;

import static com.vendo.security_lib.constants.AuthConstants.BEARER_PREFIX;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {
    @InjectMocks
    AuthService authService;
    @Mock
    private UserQueryPort userQueryPort;
    @Mock
    private TokenGenerationService tokenGenerationService;
    @Mock
    private PasswordHashingPort passwordHashingPort;
    @Mock
    private UserCommandPort userCommandPort;
    @Mock
    private BearerTokenExtractor bearerTokenExtractor;
    @Mock
    private JwtClaimsParser jwtClaimsParser;

    private final String TEST_EMAIL = "email@gmail.com";
    private final String TEST_PASSWORD = "Password123";

    @Test
    void signIn_shouldReturnTokenPayload_WhenUserIsValidAndPasswordsMatch() {
        User user = UserDataBuilder.buildUserAllFields().email(TEST_EMAIL).password(TEST_PASSWORD).build();
        AuthCommand authCommand = new AuthCommand(TEST_EMAIL, TEST_PASSWORD);
        TokenPayload tokenPayload = TokenPayloadDataBuilder.buildTokenPayloadWithAllFields().build();

        when(userQueryPort.getByEmail(authCommand.email())).thenReturn(user);
        when(tokenGenerationService.generate(user)).thenReturn(tokenPayload);
        when(passwordHashingPort.matches(authCommand.password(), user.password())).thenReturn(true);

        AuthResponse authResponse = authService.signIn(authCommand);

        assertThat(authResponse.accessToken()).isEqualTo(tokenPayload.accessToken());
        assertThat(authResponse.refreshToken()).isEqualTo(tokenPayload.refreshToken());

        verify(userQueryPort).getByEmail(authCommand.email());
        verify(tokenGenerationService).generate(user);
    }
    @Test
    void signIn_shouldThrowUserBlockedException_whenUserIsBlocked() {
        User user = UserDataBuilder.buildUserAllFields().status(UserStatus.BLOCKED).build();
        AuthCommand authCommand = new AuthCommand(TEST_EMAIL, TEST_PASSWORD);
        when(userQueryPort.getByEmail(authCommand.email())).thenReturn(user);

        assertThatThrownBy(() -> authService.signIn(authCommand)).isInstanceOf(UserBlockedException.class).hasMessage("User is blocked.");;

        verify(passwordHashingPort, never()).matches(any(), any());
        verify(tokenGenerationService, never()).generate(any());
    }
    @Test
    void signUp_shouldSignUp_whenEmailNotExists(){
        String encodedPassword = "encoded_password";
        AuthCommand authCommand = new AuthCommand(TEST_EMAIL, TEST_PASSWORD);

        when(userQueryPort.existsByEmail(authCommand.email())).thenReturn(false);
        when(passwordHashingPort.hash(authCommand.password())).thenReturn(encodedPassword);

        authService.signUp(authCommand);

        verify(passwordHashingPort).hash(authCommand.password());
        verify(userCommandPort).save(User.builder()
                .email(authCommand.email())
                .status(UserStatus.INCOMPLETE)
                .role(UserRole.USER)
                .providerType(ProviderType.LOCAL)
                .password(encodedPassword)
                .build());
    }
    @Test
    void signUp_shouldThrowUserAlreadyExistsException_whenEmailExists(){
        AuthCommand authCommand = new AuthCommand(TEST_EMAIL, TEST_PASSWORD);

        when(userQueryPort.existsByEmail(authCommand.email())).thenReturn(true);

        assertThatThrownBy(() -> authService.signUp(authCommand)).isInstanceOf(UserAlreadyExistsException.class);

        verify(userQueryPort).existsByEmail(authCommand.email());
        verify(passwordHashingPort, never()).hash(any());
        verify(userCommandPort, never()).save(any());
    }
    @Test
    void completeAuth_shouldUpdateUser_WhenUserIsValid(){
        CompleteAuthCommand completeAuthCommand = new CompleteAuthCommand("Full Name", LocalDate.of(2000, 1, 1));
        User user = UserDataBuilder.buildUserAllFields().status(UserStatus.INCOMPLETE).email(TEST_EMAIL).build();

        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);

        authService.completeAuth(TEST_EMAIL, completeAuthCommand);

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(userCommandPort).update(user.id(), User.builder()
                .status(UserStatus.ACTIVE)
                .fullName(completeAuthCommand.fullName())
                .birthDate(completeAuthCommand.birthDate())
                .build());
    }
    @Test
    void completeAuth_shouldThrowUserBlockedException_WhenUserIsBlocked(){
        CompleteAuthCommand completeAuthCommand = new CompleteAuthCommand("Full Name", LocalDate.of(2000, 1, 1));
        User user = UserDataBuilder.buildUserAllFields().email(TEST_EMAIL).status(UserStatus.BLOCKED).build();

        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);
        assertThatThrownBy(() -> authService.completeAuth(TEST_EMAIL, completeAuthCommand)).isInstanceOf(UserBlockedException.class).hasMessage("User is blocked.");

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(userCommandPort, never()).update(any(), any());
    }
    @Test
    void completeAuth_shouldThrowUserNotFoundException_WhenNoUserFound(){
        CompleteAuthCommand completeAuthCommand = new CompleteAuthCommand("Full Name", LocalDate.of(2000, 1, 1));

        when(userQueryPort.getByEmail(TEST_EMAIL)).thenThrow(new UserNotFoundException("User not found."));;

        assertThatThrownBy(() -> authService.completeAuth(TEST_EMAIL, completeAuthCommand)).isInstanceOf(UserNotFoundException.class).hasMessage("User not found.");;

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(userCommandPort, never()).update(any(), any());
    }
    @Test
    void refresh_shouldReturnTokens_whenRefreshTokenIsValid(){
        String rawToken = "raw-token";
        String bearerRefreshToken = BEARER_PREFIX + rawToken;
        TokenPayload tokenPayload = TokenPayloadDataBuilder.buildTokenPayloadWithAllFields()
                .refreshToken("refresh-token")
                .accessToken("access-token")
                .build();
        User user = UserDataBuilder.buildUserAllFields().email(TEST_EMAIL).build();
        RefreshCommand refreshCommand = new RefreshCommand(bearerRefreshToken);

        when(bearerTokenExtractor.extract(refreshCommand.refreshToken())).thenReturn(rawToken);
        when(jwtClaimsParser.extractSubject(rawToken)).thenReturn(TEST_EMAIL);
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);
        when(tokenGenerationService.generate(user)).thenReturn(tokenPayload);

        AuthResponse authResponse = authService.refresh(refreshCommand);

        verify(bearerTokenExtractor).extract(refreshCommand.refreshToken());
        verify(jwtClaimsParser).extractSubject(rawToken);
        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(tokenGenerationService).generate(user);

        assertThat(authResponse.refreshToken()).isEqualTo("refresh-token");
        assertThat(authResponse.accessToken()).isEqualTo("access-token");
    }
    @Test
    void refresh_shouldThrowInvalidTokenException_whenHasNoBearerPrefix(){
        RefreshCommand refreshCommand = new RefreshCommand("refresh-token");

        when(bearerTokenExtractor.extract(refreshCommand.refreshToken())).thenThrow(new InvalidTokenException("Invalid token."));

        assertThatThrownBy(() -> authService.refresh(refreshCommand)).isInstanceOf(InvalidTokenException.class).hasMessage("Invalid token.");

        verify(bearerTokenExtractor).extract(refreshCommand.refreshToken());
        verifyNoInteractions(jwtClaimsParser, userQueryPort, tokenGenerationService);

    }
    @Test
    void refresh_shouldThrowUserNotFoundException_whenNoUserFound(){
        String rawToken = "raw-token";
        String bearerRefreshToken = BEARER_PREFIX + rawToken;
        RefreshCommand refreshCommand = new RefreshCommand(bearerRefreshToken);

        when(bearerTokenExtractor.extract(refreshCommand.refreshToken())).thenReturn(rawToken);
        when(jwtClaimsParser.extractSubject(rawToken)).thenReturn(TEST_EMAIL);
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenThrow(new UserNotFoundException("User not found."));

        assertThatThrownBy(() -> authService.refresh(refreshCommand)).isInstanceOf(UserNotFoundException.class).hasMessage("User not found.");

        verify(bearerTokenExtractor).extract(refreshCommand.refreshToken());
        verify(jwtClaimsParser).extractSubject(rawToken);
        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verifyNoInteractions(tokenGenerationService);
    }
}
