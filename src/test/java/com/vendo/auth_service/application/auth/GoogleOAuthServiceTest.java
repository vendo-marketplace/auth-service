package com.vendo.auth_service.application.auth;

import com.vendo.auth_service.adapter.auth.in.dto.GoogleAuthRequest;
import com.vendo.auth_service.application.auth.dto.*;
import com.vendo.auth_service.domain.auth.dto.TokenPayloadDataBuilder;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.auth.GoogleTokenVerifierPort;
import com.vendo.auth_service.port.security.TokenGenerationPort;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.user_lib.exception.UserNotFoundException;
import com.vendo.user_lib.type.ProviderType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
class GoogleOAuthServiceTest {

    @InjectMocks
    private GoogleOAuthService googleOAuthService;

    @Mock
    private UserCommandPort userCommandPort;

    @Mock
    private UserQueryPort userQueryPort;

    @Mock
    private TokenGenerationPort tokenGenerationPort;

    @Mock
    private GoogleTokenVerifierPort googleTokenVerifierPort;

    @Test
    void googleAuth_shouldReturnTokenPayload_whenUserFound() {
        TokenPayload tokenPayload = TokenPayloadDataBuilder.withAllFields().build();
        GoogleAuthRequest googleAuthRequest = new GoogleAuthRequest("test_id_token");
        User user = UserDataBuilder.withAllFields().build();
        String idToken = "test_id_token";
        String email = "test_email";
        GoogleTokenPayload mockPayload = mock(GoogleTokenPayload.class);

        when(googleTokenVerifierPort.verify(idToken)).thenReturn(mockPayload);
        when(mockPayload.email()).thenReturn(email);
        when(userQueryPort.getByEmail(email)).thenReturn(user);
        when(tokenGenerationPort.generate(user)).thenReturn(tokenPayload);

        AuthResponse authResponse = googleOAuthService.googleAuth(googleAuthRequest);
        assertThat(authResponse).isNotNull();
        assertThat(authResponse.accessToken()).isEqualTo(tokenPayload.accessToken());
        assertThat(authResponse.refreshToken()).isEqualTo(tokenPayload.refreshToken());

        verify(googleTokenVerifierPort).verify(idToken);
        verify(userQueryPort).getByEmail(email);
        verify(userCommandPort, never()).update(anyString(), any(UpdateUserRequest.class));
        verify(tokenGenerationPort).generate(user);
    }

    @Test
    void googleAuth_shouldCreateUser_andReturnTokenPayload_whenUserNotFound() {
        TokenPayload tokenPayload = TokenPayloadDataBuilder.withAllFields().build();
        GoogleAuthRequest googleAuthRequest = new GoogleAuthRequest("test_id_token");

        User user = UserDataBuilder.withAllFields().providerType(null).status(null).build();
        String idToken = "test_id_token";
        String email = "test_email";
        GoogleTokenPayload mockPayload = mock(GoogleTokenPayload.class);
        ArgumentCaptor<SaveUserRequest> captor = ArgumentCaptor.forClass(SaveUserRequest.class);

        when(googleTokenVerifierPort.verify(idToken)).thenReturn(mockPayload);
        when(mockPayload.email()).thenReturn(email);
        when(userQueryPort.getByEmail(email)).thenThrow(UserNotFoundException.class);
        when(userCommandPort.save(captor.capture())).thenReturn(user);
        when(tokenGenerationPort.generate(user)).thenReturn(tokenPayload);

        AuthResponse authResponse = googleOAuthService.googleAuth(googleAuthRequest);

        assertThat(authResponse).isNotNull();
        assertThat(authResponse.accessToken()).isEqualTo(tokenPayload.accessToken());
        assertThat(authResponse.refreshToken()).isEqualTo(tokenPayload.refreshToken());

        SaveUserRequest value = captor.getValue();
        verify(googleTokenVerifierPort).verify(idToken);
        verify(userQueryPort).getByEmail(email);
        verify(userCommandPort).save(value);
        verify(tokenGenerationPort).generate(user);

        assertThat(value.email()).isEqualTo(email);
        assertThat(value.providerType()).isEqualTo(ProviderType.GOOGLE);
    }

    @Test
    void googleAuth_shouldThrowException_whenIdTokenNotVerified() {
        GoogleAuthRequest googleAuthRequest = new GoogleAuthRequest("test_id_token");
        String idToken = "test_id_token";

        when(googleTokenVerifierPort.verify(idToken)).thenThrow(BadCredentialsException.class);

        assertThatThrownBy(() -> googleOAuthService.googleAuth(googleAuthRequest))
                .isInstanceOf(BadCredentialsException.class);

        verify(googleTokenVerifierPort).verify(idToken);
        verifyNoInteractions(userQueryPort, userCommandPort, tokenGenerationPort);
    }
}
