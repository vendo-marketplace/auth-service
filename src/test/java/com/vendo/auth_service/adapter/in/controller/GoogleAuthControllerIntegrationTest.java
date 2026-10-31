package com.vendo.auth_service.adapter.in.controller;

import com.vendo.auth_service.application.auth.dto.GoogleTokenPayload;
import com.vendo.auth_service.application.auth.dto.SaveUserRequest;
import com.vendo.auth_service.application.auth.dto.TokenPayload;
import com.vendo.auth_service.domain.auth.dto.TokenPayloadDataBuilder;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.auth.GoogleAuthCodePort;
import com.vendo.auth_service.port.auth.GoogleTokenVerifierPort;
import com.vendo.auth_service.port.security.TokenGenerationPort;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.user_lib.exception.UserNotFoundException;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class GoogleAuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;
    @MockitoBean
    private UserQueryPort userQueryPort;
    @MockitoBean
    private UserCommandPort userCommandPort;
    @MockitoBean
    private TokenGenerationPort tokenGenerationPort;
    @MockitoBean
    private GoogleTokenVerifierPort googleTokenVerifierPort;
    @MockitoBean
    private GoogleAuthCodePort googleAuthCodePort;

    @Test
    void googleAuth_shouldSetAuthCookies_whenExistingGoogleUserEmailIsVerified() throws Exception {
        String authCode = "test_auth_code";
        String idToken = "test_id_token";
        String email = "verified.google@gmail.com";
        String fullName = "Verified Google User";
        GoogleTokenPayload googleTokenPayload = GoogleTokenPayload.builder()
                .email(email)
                .fullName(fullName)
                .build();
        User user = UserDataBuilder.withAllFields()
                .email(email)
                .providerType(ProviderType.GOOGLE)
                .emailVerified(true)
                .build();
        TokenPayload tokenPayload = TokenPayloadDataBuilder.withAllFields().build();
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

        when(googleAuthCodePort.exchange(authCode)).thenReturn(idToken);
        when(googleTokenVerifierPort.verify(idToken)).thenReturn(googleTokenPayload);
        when(userQueryPort.getByEmail(email)).thenReturn(user);
        when(tokenGenerationPort.generate(user)).thenReturn(tokenPayload);

        var response = mockMvc.perform(post("/auth/google")
                        .param("authCode", authCode))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse();

        assertThat(response.getContentAsString()).isEmpty();
        assertThat(response.getHeaders(HttpHeaders.SET_COOKIE).size()).isEqualTo(2);
        assertThat(response.getHeaders(HttpHeaders.SET_COOKIE).get(0))
                .contains("accessToken=" + tokenPayload.accessToken(), "Path=/", "HttpOnly", "Secure", "SameSite=Lax");
        assertThat(response.getHeaders(HttpHeaders.SET_COOKIE).get(1))
                .contains("refreshToken=" + tokenPayload.refreshToken(), "Path=/auth/refresh", "HttpOnly", "Secure", "SameSite=Lax");

        verify(googleAuthCodePort).exchange(authCode);
        verify(googleTokenVerifierPort).verify(idToken);
        verify(userQueryPort).getByEmail(email);
        verify(tokenGenerationPort).generate(userCaptor.capture());
        assertThat(userCaptor.getValue().emailVerified()).isTrue();
        assertThat(userCaptor.getValue().providerType()).isEqualTo(ProviderType.GOOGLE);
        verifyNoInteractions(userCommandPort);
    }

    @Test
    void googleAuth_shouldCreateVerifiedGoogleUser_andSetAuthCookies_whenUserNotFound() throws Exception {
        String authCode = "test_auth_code";
        String idToken = "test_id_token";
        String email = "new.google@gmail.com";
        String fullName = "New Google User";
        GoogleTokenPayload googleTokenPayload = GoogleTokenPayload.builder()
                .email(email)
                .fullName(fullName)
                .build();
        User verifiedUser = UserDataBuilder.withAllFields()
                .email(email)
                .fullName(fullName)
                .providerType(ProviderType.GOOGLE)
                .emailVerified(true)
                .build();
        TokenPayload tokenPayload = TokenPayloadDataBuilder.withAllFields().build();
        ArgumentCaptor<SaveUserRequest> saveUserCaptor =
                ArgumentCaptor.forClass(SaveUserRequest.class);
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

        when(googleAuthCodePort.exchange(authCode)).thenReturn(idToken);
        when(googleTokenVerifierPort.verify(idToken)).thenReturn(googleTokenPayload);
        when(userQueryPort.getByEmail(email)).thenThrow(UserNotFoundException.class);
        when(userCommandPort.save(saveUserCaptor.capture())).thenReturn(verifiedUser);
        when(tokenGenerationPort.generate(verifiedUser)).thenReturn(tokenPayload);

        var response = mockMvc.perform(post("/auth/google")
                        .param("authCode", authCode))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse();

        assertThat(response.getContentAsString()).isEmpty();
        assertThat(response.getHeaders(HttpHeaders.SET_COOKIE).size()).isEqualTo(2);
        assertThat(response.getHeaders(HttpHeaders.SET_COOKIE).get(0))
                .contains("accessToken=" + tokenPayload.accessToken(), "Path=/", "HttpOnly", "Secure", "SameSite=Lax");
        assertThat(response.getHeaders(HttpHeaders.SET_COOKIE).get(1))
                .contains("refreshToken=" + tokenPayload.refreshToken(), "Path=/auth/refresh", "HttpOnly", "Secure", "SameSite=Lax");

        SaveUserRequest saveUserRequest = saveUserCaptor.getValue();
        assertThat(saveUserRequest.email()).isEqualTo(email);
        assertThat(saveUserRequest.fullName()).isEqualTo(fullName);
        assertThat(saveUserRequest.providerType()).isEqualTo(ProviderType.GOOGLE);
        assertThat(saveUserRequest.roles().contains(UserRole.USER)).isTrue();
        assertThat(saveUserRequest.status()).isEqualTo(UserStatus.ACTIVE);

        verify(googleAuthCodePort).exchange(authCode);
        verify(googleTokenVerifierPort).verify(idToken);
        verify(userQueryPort).getByEmail(email);
        verify(userCommandPort).save(saveUserRequest);
        verify(tokenGenerationPort).generate(userCaptor.capture());
        assertThat(userCaptor.getValue().emailVerified()).isTrue();
        assertThat(userCaptor.getValue().providerType()).isEqualTo(ProviderType.GOOGLE);
    }
}
