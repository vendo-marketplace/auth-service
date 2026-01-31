package com.vendo.auth_service.application.google;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.vendo.auth_service.adapter.in.web.dto.AuthResponse;
import com.vendo.auth_service.adapter.in.web.dto.GoogleAuthRequest;
import com.vendo.auth_service.adapter.out.security.common.dto.TokenPayload;
import com.vendo.auth_service.domain.auth.dto.TokenPayloadDataBuilder;
import com.vendo.auth_service.domain.user.common.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.port.security.TokenGenerationService;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.security.common.exception.AccessDeniedException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
public class GoogleOAuthServiceTest {

    @InjectMocks
    private GoogleOAuthService googleOAuthService;

    @Mock
    private UserCommandPort userCommandPort;

    @Mock
    private TokenGenerationService tokenGenerationService;

    @Mock
    private GoogleTokenVerifier googleTokenVerifier;

    @Test
    void googleAuth_shouldReturnTokenPayload() {
        TokenPayload tokenPayload = TokenPayloadDataBuilder.buildTokenPayloadWithAllFields().build();
        GoogleAuthRequest googleAuthRequest = new GoogleAuthRequest("test_id_token");
        User user = UserDataBuilder.buildUserAllFields().build();
        String idToken = "test_id_token";
        String email = "test_email";
        GoogleIdToken.Payload mockPayload = mock(GoogleIdToken.Payload.class);

        when(googleTokenVerifier.verify(idToken)).thenReturn(mockPayload);
        when(mockPayload.getEmail()).thenReturn(email);
        when(userCommandPort.ensureExists(email)).thenReturn(user);
        when(tokenGenerationService.generate(user)).thenReturn(tokenPayload);

        AuthResponse authResponse = googleOAuthService.googleAuth(googleAuthRequest);
        assertThat(authResponse).isNotNull();
        assertThat(authResponse.accessToken()).isEqualTo(tokenPayload.accessToken());
        assertThat(authResponse.refreshToken()).isEqualTo(tokenPayload.refreshToken());

        verify(googleTokenVerifier).verify(idToken);
        verify(userCommandPort).ensureExists(email);
        verify(userCommandPort, never()).update(anyString(), any(UpdateUserRequest.class));
        verify(tokenGenerationService).generate(user);
    }

    @Test
    void googleAuth_shouldActivateIncompletedUser_andReturnTokenPayload() {
        TokenPayload tokenPayload = TokenPayloadDataBuilder.buildTokenPayloadWithAllFields().build();
        GoogleAuthRequest googleAuthRequest = new GoogleAuthRequest("test_id_token");
        User user = UserDataBuilder.buildUserAllFields().status(UserStatus.INCOMPLETE).build();
        String idToken = "test_id_token";
        String email = "test_email";
        GoogleIdToken.Payload mockPayload = mock(GoogleIdToken.Payload.class);

        when(googleTokenVerifier.verify(idToken)).thenReturn(mockPayload);
        when(mockPayload.getEmail()).thenReturn(email);
        when(userCommandPort.ensureExists(email)).thenReturn(user);
        when(tokenGenerationService.generate(user)).thenReturn(tokenPayload);

        AuthResponse authResponse = googleOAuthService.googleAuth(googleAuthRequest);

        assertThat(authResponse).isNotNull();
        assertThat(authResponse.accessToken()).isEqualTo(tokenPayload.accessToken());
        assertThat(authResponse.refreshToken()).isEqualTo(tokenPayload.refreshToken());

        ArgumentCaptor<UpdateUserRequest> updateUserRequestArgumentCaptor = ArgumentCaptor.forClass(UpdateUserRequest.class);
        verify(googleTokenVerifier).verify(idToken);
        verify(userCommandPort).ensureExists(email);
        verify(userCommandPort).update(eq(user.id()), updateUserRequestArgumentCaptor.capture());
        verify(tokenGenerationService).generate(user);

        UpdateUserRequest updateUserRequest = updateUserRequestArgumentCaptor.getValue();
        assertThat(updateUserRequest.status()).isEqualTo(UserStatus.ACTIVE);
        assertThat(updateUserRequest.providerType()).isEqualTo(ProviderType.GOOGLE);
    }

    @Test
    void googleAuth_shouldNotUpdateProviderTypeToGoogle_whenUserIsActive() {
        TokenPayload tokenPayload = TokenPayloadDataBuilder.buildTokenPayloadWithAllFields().build();
        GoogleAuthRequest googleAuthRequest = new GoogleAuthRequest("test_id_token");
        User user = UserDataBuilder.buildUserAllFields().status(UserStatus.ACTIVE).build();
        String idToken = "test_id_token";
        String email = "test_email";
        GoogleIdToken.Payload mockPayload = mock(GoogleIdToken.Payload.class);

        when(googleTokenVerifier.verify(idToken)).thenReturn(mockPayload);
        when(mockPayload.getEmail()).thenReturn(email);
        when(userCommandPort.ensureExists(email)).thenReturn(user);
        when(tokenGenerationService.generate(user)).thenReturn(tokenPayload);

        AuthResponse authResponse = googleOAuthService.googleAuth(googleAuthRequest);

        assertThat(authResponse).isNotNull();
        assertThat(authResponse.accessToken()).isEqualTo(tokenPayload.accessToken());
        assertThat(authResponse.refreshToken()).isEqualTo(tokenPayload.refreshToken());

        verify(googleTokenVerifier).verify(idToken);
        verify(userCommandPort).ensureExists(email);
        verify(tokenGenerationService).generate(user);
        verify(userCommandPort, never()).update(eq(user.id()), any(UpdateUserRequest.class));
    }

    @Test
    void googleAuth_shouldThrowException_whenIdTokenNotVerified() {
        GoogleAuthRequest googleAuthRequest = new GoogleAuthRequest("test_id_token");
        User user = UserDataBuilder.buildUserAllFields().build();
        String idToken = "test_id_token";
        String email = "test_email";

        when(googleTokenVerifier.verify(idToken)).thenThrow(AccessDeniedException.class);

        assertThatThrownBy(() -> googleOAuthService.googleAuth(googleAuthRequest))
                .isInstanceOf(AccessDeniedException.class);

        verify(googleTokenVerifier).verify(idToken);
        verify(userCommandPort, never()).ensureExists(email);
        verify(tokenGenerationService, never()).generate(user);
    }

}
