package com.vendo.auth_service.adapter.in.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.auth_service.adapter.common.JwtGenerator;
import com.vendo.auth_service.adapter.in.security.SecurityContextHelper;
import com.vendo.auth_service.adapter.in.security.dto.AuthUser;
import com.vendo.auth_service.adapter.in.web.dto.*;
import com.vendo.auth_service.adapter.out.security.common.dto.TokenPayload;
import com.vendo.auth_service.adapter.out.security.helper.JwtHelper;
import com.vendo.auth_service.adapter.out.security.service.JwtService;
import com.vendo.auth_service.domain.auth.dto.AuthRequestDataBuilder;
import com.vendo.auth_service.domain.auth.dto.AuthUserDataBuilder;
import com.vendo.auth_service.domain.auth.dto.CompleteAuthRequestDataBuilder;
import com.vendo.auth_service.domain.auth.dto.TokenPayloadDataBuilder;
import com.vendo.auth_service.domain.user.common.dto.SaveUserRequest;
import com.vendo.auth_service.domain.user.common.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.auth_service.domain.user.common.exception.UserNotFoundException;
import com.vendo.auth_service.domain.user.dto.SaveUserRequestDataBuilder;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.common.exception.ExceptionResponse;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserRole;
import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.security.common.exception.InvalidTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.kafka.test.context.EmbeddedKafka;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDate;

import static com.vendo.auth_service.adapter.common.SecurityContextService.initializeSecurityContext;
import static com.vendo.security.common.constants.AuthConstants.AUTHORIZATION_HEADER;
import static com.vendo.security.common.constants.AuthConstants.BEARER_PREFIX;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@EmbeddedKafka
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private UserQueryPort userQueryPort;

    @MockitoBean
    private UserCommandPort userCommandPort;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private JwtHelper jwtHelper;

    @MockitoBean
    private JwtGenerator jwtGenerator;

    @MockitoBean
    private SecurityContextHelper securityContextHelper;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Nested
    class SignUpTests {

        @Test
        void signUp_shouldSuccessfullyRegisterUser() throws Exception {
            AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();
            SaveUserRequest saveUserRequest = SaveUserRequestDataBuilder.buildWithAllFields().build();
            User user = UserDataBuilder.buildUserAllFields()
                    .email(authRequest.email())
                    .build();
            String encodedPassword = "encoded_password";

            when(userQueryPort.existsByEmail(authRequest.email())).thenReturn(false);
            when(passwordEncoder.encode(authRequest.password())).thenReturn(encodedPassword);
            when(userCommandPort.save(saveUserRequest)).thenReturn(user);

            mockMvc.perform(post("/auth/sign-up")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authRequest)))
                    .andExpect(status().isOk());

            ArgumentCaptor<SaveUserRequest> saveUserRequestArgumentCaptor = ArgumentCaptor.forClass(SaveUserRequest.class);
            verify(userQueryPort).existsByEmail(authRequest.email());
            verify(userCommandPort).save(saveUserRequestArgumentCaptor.capture());

            SaveUserRequest userRequestArgumentCaptorValue = saveUserRequestArgumentCaptor.getValue();
            assertThat(userRequestArgumentCaptorValue.email()).isEqualTo(authRequest.email());
            assertThat(userRequestArgumentCaptorValue.password()).isEqualTo(encodedPassword);
            assertThat(userRequestArgumentCaptorValue.role()).isEqualTo(UserRole.USER);
            assertThat(userRequestArgumentCaptorValue.status()).isEqualTo(UserStatus.INCOMPLETE);
            assertThat(userRequestArgumentCaptorValue.providerType()).isEqualTo(ProviderType.LOCAL);
        }

        @Test
        void signUp_shouldReturnConflict_whenUserAlreadyExists() throws Exception {
            AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();

            when(userQueryPort.existsByEmail(authRequest.email())).thenReturn(true);

            String content = mockMvc.perform(post("/auth/sign-up")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authRequest)))
                    .andExpect(status().isConflict())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotBlank();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse.getMessage()).isEqualTo("User already exists.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/sign-up");

            verify(userQueryPort).existsByEmail(authRequest.email());
            verify(passwordEncoder, never()).encode(anyString());
            verify(userCommandPort, never()).save(any(SaveUserRequest.class));
        }
    }

    @Nested
    class SignInTests {

        @Test
        void signIn_shouldReturnPairOfTokens() throws Exception {
            AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();
            User user = UserDataBuilder.buildUserAllFields()
                    .status(UserStatus.ACTIVE)
                    .email(authRequest.email())
                    .emailVerified(true)
                    .password(passwordEncoder.encode(authRequest.password()))
                    .build();
            TokenPayload tokenPayload = TokenPayloadDataBuilder.buildTokenPayloadWithAllFields().build();

            when(userQueryPort.getByEmail(authRequest.email())).thenReturn(user);
            when(passwordEncoder.matches(authRequest.password(), user.password())).thenReturn(true);
            when(jwtService.generateTokensPair(user)).thenReturn(tokenPayload);

            String content = mockMvc.perform(post("/auth/sign-in")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authRequest)))
                    .andExpect(status().isOk())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotBlank();
            AuthResponse authResponse = objectMapper.readValue(content, AuthResponse.class);

            assertThat(authResponse).isNotNull();
            assertThat(authResponse.accessToken()).isNotBlank();
            assertThat(authResponse.refreshToken()).isNotBlank();

            verify(userQueryPort).getByEmail(authRequest.email());
            verify(passwordEncoder).matches(authRequest.password(), user.password());
            verify(jwtService).generateTokensPair(user);
        }

        @Test
        void signIn_shouldReturnNotFound_whenUserNotFound() throws Exception {
            AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();

            when(userQueryPort.getByEmail(authRequest.email())).thenThrow(new UserNotFoundException("User not found."));

            MockHttpServletResponse response = mockMvc.perform(post("/auth/sign-in")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authRequest)))
                    .andExpect(status().isNotFound()).andReturn().getResponse();

            String responseContent = response.getContentAsString();
            assertThat(responseContent).isNotBlank();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("User not found.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/sign-in");

            verify(userQueryPort).getByEmail(authRequest.email());
            verify(passwordEncoder, never()).matches(anyString(), anyString());
            verify(jwtService, never()).generateTokensPair(any(User.class));
        }

        @Test
        void signIn_shouldReturnForbidden_whenUserBlocked() throws Exception {
            AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();
            User user = UserDataBuilder.buildUserAllFields()
                    .status(UserStatus.BLOCKED)
                    .email(authRequest.email())
                    .password(passwordEncoder.encode(authRequest.password()))
                    .build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            String content = mockMvc.perform(post("/auth/sign-in")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authRequest)))
                    .andExpect(status().isForbidden())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotBlank();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse.getMessage()).isEqualTo("User is blocked.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/sign-in");

            verify(userQueryPort).getByEmail(user.email());
            verify(passwordEncoder, never()).matches(authRequest.password(), user.password());
            verify(jwtService, never()).generateTokensPair(user);
        }

        @Test
        void signIn_shouldReturnForbidden_whenUserIncomplete() throws Exception {
            AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();
            User user = UserDataBuilder.buildUserAllFields()
                    .status(UserStatus.INCOMPLETE)
                    .emailVerified(true)
                    .email(authRequest.email())
                    .password(passwordEncoder.encode(authRequest.password()))
                    .build();

            when(userQueryPort.getByEmail(authRequest.email())).thenReturn(user);

            String content = mockMvc.perform(post("/auth/sign-in")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authRequest)))
                    .andExpect(status().isForbidden())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotBlank();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse.getMessage()).isEqualTo("User is unactive.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/sign-in");

            verify(userQueryPort).getByEmail(user.email());
            verify(passwordEncoder, never()).matches(authRequest.password(), user.password());
            verify(jwtService, never()).generateTokensPair(user);
        }

        @Test
        void signIn_shouldReturnForbidden_whenUserEmailIsNotVerified() throws Exception {
            AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();
            User user = UserDataBuilder.buildUserAllFields()
                    .status(UserStatus.INCOMPLETE)
                    .emailVerified(false)
                    .email(authRequest.email())
                    .password(passwordEncoder.encode(authRequest.password()))
                    .build();

            when(userQueryPort.getByEmail(authRequest.email())).thenReturn(user);

            String content = mockMvc.perform(post("/auth/sign-in")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authRequest)))
                    .andExpect(status().isForbidden())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotBlank();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse.getMessage()).isEqualTo("User email is not verified.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/sign-in");

            verify(userQueryPort).getByEmail(user.email());
            verify(passwordEncoder, never()).matches(authRequest.password(), user.password());
            verify(jwtService, never()).generateTokensPair(user);
        }
    }

    @Nested
    class RefreshTests {

        @Test
        void refresh_shouldReturnPairOfTokens() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();
            RefreshRequest refreshRequest = RefreshRequest.builder().refreshToken(BEARER_PREFIX + "refresh_token").build();
            TokenPayload tokenPayload = TokenPayloadDataBuilder.buildTokenPayloadWithAllFields().build();

            when(jwtService.parseBearerToken(refreshRequest.refreshToken())).thenReturn(refreshRequest.refreshToken());
            when(jwtService.parseEmailFromToken(refreshRequest.refreshToken())).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            when(jwtService.generateTokensPair(user)).thenReturn(tokenPayload);

            String content = mockMvc.perform(post("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(refreshRequest)))
                    .andExpect(status().isOk())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotBlank();
            AuthResponse authResponse = objectMapper.readValue(content, AuthResponse.class);

            assertThat(authResponse).isNotNull();
            assertThat(authResponse.accessToken()).isNotBlank();
            assertThat(authResponse.refreshToken()).isNotBlank();

            verify(jwtService).parseBearerToken(refreshRequest.refreshToken());
            verify(jwtService).parseEmailFromToken(refreshRequest.refreshToken());
            verify(userQueryPort).getByEmail(user.email());
            verify(jwtService).generateTokensPair(user);
        }

        @Test
        void refresh_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();
            RefreshRequest refreshRequest = RefreshRequest.builder().refreshToken(BEARER_PREFIX + "refresh_token").build();

            when(jwtService.parseBearerToken(refreshRequest.refreshToken())).thenReturn(refreshRequest.refreshToken());
            when(jwtService.parseEmailFromToken(refreshRequest.refreshToken())).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenThrow(new UserNotFoundException("User not found."));

            String content = mockMvc.perform(post("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(refreshRequest)))
                    .andExpect(status().isNotFound())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotBlank();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse.getMessage()).isEqualTo("User not found.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/refresh");

            verify(jwtService).parseBearerToken(refreshRequest.refreshToken());
            verify(jwtService).parseEmailFromToken(refreshRequest.refreshToken());
            verify(userQueryPort).getByEmail(user.email());
            verify(jwtService, never()).generateTokensPair(user);
        }

        @Test
        void refresh_shouldReturnUnauthorized_whenTokenWithoutBearerPrefix() throws Exception {
            RefreshRequest refreshRequest = RefreshRequest.builder().refreshToken("refresh_token").build();

            when(jwtService.parseBearerToken(refreshRequest.refreshToken())).thenThrow(new InvalidTokenException("Invalid token."));

            String content = mockMvc.perform(post("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(refreshRequest)))
                    .andExpect(status().isUnauthorized())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotBlank();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse.getMessage()).isEqualTo("Invalid token.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/refresh");

            verify(jwtService).parseBearerToken(refreshRequest.refreshToken());
            verify(jwtService, never()).parseEmailFromToken(anyString());
            verify(userQueryPort, never()).getByEmail(anyString());
            verify(jwtService, never()).generateTokensPair(any(User.class));
        }

        @Test
        void refresh_shouldReturnUnauthorized_whenTokenIsExpired() throws Exception {
            RefreshRequest refreshRequest = RefreshRequest.builder().refreshToken(BEARER_PREFIX + "refresh_token").build();

            when(jwtService.parseBearerToken(refreshRequest.refreshToken())).thenReturn(refreshRequest.refreshToken());
            when(jwtService.parseEmailFromToken(refreshRequest.refreshToken())).thenThrow(ExpiredJwtException.class);

            String content = mockMvc.perform(post("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(refreshRequest)))
                    .andExpect(status().isUnauthorized())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotBlank();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse.getMessage()).isEqualTo("Token has expired.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/refresh");

            verify(jwtService).parseBearerToken(refreshRequest.refreshToken());
            verify(jwtService).parseEmailFromToken(refreshRequest.refreshToken());
            verify(userQueryPort, never()).getByEmail(anyString());
            verify(jwtService, never()).generateTokensPair(any(User.class));
        }
    }

    @Nested
    class CompleteAuthTests {

        @Test
        void completeAuth_shouldSuccessfullyCompleteRegistration() throws Exception {
            User user = UserDataBuilder.buildUserAllFields()
                    .status(UserStatus.INCOMPLETE)
                    .emailVerified(false)
                    .build();
            CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder.buildCompleteAuthRequestWithAllFields().build();
            ArgumentCaptor<UpdateUserRequest> updateUserRequestArgumentCaptor = ArgumentCaptor.forClass(UpdateUserRequest.class);

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            doNothing().when(userCommandPort).update(eq(user.id()), updateUserRequestArgumentCaptor.capture());

            mockMvc.perform(patch("/auth/complete-auth")
                            .param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(completeAuthRequest)))
                    .andExpect(status().isOk());

            UpdateUserRequest updateUserRequest = updateUserRequestArgumentCaptor.getValue();
            verify(userQueryPort).getByEmail(user.email());
            verify(userCommandPort).update(user.id(), updateUserRequest);

            UpdateUserRequest userRequestArgumentCaptorValue = updateUserRequestArgumentCaptor.getValue();
            assertThat(userRequestArgumentCaptorValue).isNotNull();
            assertThat(userRequestArgumentCaptorValue.status()).isEqualTo(updateUserRequest.status());
            assertThat(userRequestArgumentCaptorValue.fullName()).isEqualTo(updateUserRequest.fullName());
            assertThat(userRequestArgumentCaptorValue.birthDate()).isEqualTo(updateUserRequest.birthDate());
        }

        @Test
        void completeAuth_shouldReturnBadRequest_whenNotValidFullName() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();
            CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder.buildCompleteAuthRequestWithAllFields()
                    .fullName("Invalid_fullName")
                    .build();

            String content = mockMvc.perform(patch("/auth/complete-auth")
                            .param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(completeAuthRequest)))
                    .andExpect(status().isBadRequest())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotNull();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse).isNotNull();
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/complete-auth");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
            assertThat(exceptionResponse.getErrors()).isNotNull();
            assertThat(exceptionResponse.getErrors().size()).isEqualTo(1);
            assertThat(exceptionResponse.getErrors().get("fullName")).isNotNull();
        }

        @Test
        void completeAuth_shouldReturnBadRequest_whenNotAdult() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();
            CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder.buildCompleteAuthRequestWithAllFields()
                    .birthDate(LocalDate.now())
                    .build();

            String content = mockMvc.perform(patch("/auth/complete-auth")
                            .param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(completeAuthRequest)))
                    .andExpect(status().isBadRequest())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotNull();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse).isNotNull();
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/complete-auth");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
            assertThat(exceptionResponse.getErrors()).isNotNull();
            assertThat(exceptionResponse.getErrors().size()).isEqualTo(1);
            assertThat(exceptionResponse.getErrors().get("birthDate")).isNotNull();
        }

        @Test
        void completeAuth_shouldReturnBadRequest_whenBothNotAdultAndInvalidFullName() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();
            CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder.buildCompleteAuthRequestWithAllFields()
                    .fullName("Invalid_fullName")
                    .birthDate(LocalDate.of(2025, 1, 1))
                    .build();

            String content = mockMvc.perform(patch("/auth/complete-auth")
                            .param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(completeAuthRequest)))
                    .andExpect(status().isBadRequest())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotNull();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse).isNotNull();
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/complete-auth");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
            assertThat(exceptionResponse.getErrors()).isNotNull();
            assertThat(exceptionResponse.getErrors().size()).isEqualTo(2);
            assertThat(exceptionResponse.getErrors().get("birthDate")).isNotNull();
            assertThat(exceptionResponse.getErrors().get("fullName")).isNotNull();
        }

        @Test
        void completeAuth_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();
            CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder.buildCompleteAuthRequestWithAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenThrow(new UserNotFoundException("User not found."));

            String content = mockMvc.perform(patch("/auth/complete-auth")
                            .param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(completeAuthRequest)))
                    .andExpect(status().isNotFound())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotNull();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse).isNotNull();
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/complete-auth");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
            assertThat(exceptionResponse.getMessage()).isEqualTo("User not found.");

            verify(userQueryPort).getByEmail(user.email());
            verify(userCommandPort, never()).update(anyString(), any(UpdateUserRequest.class));
        }

        @Test
        void completeProfile_shouldReturnForbidden_whenUserBlocked() throws Exception {
            User user = UserDataBuilder.buildUserAllFields()
                    .status(UserStatus.BLOCKED)
                    .emailVerified(true)
                    .build();
            CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder.buildCompleteAuthRequestWithAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            String content = mockMvc.perform(patch("/auth/complete-auth")
                            .param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(completeAuthRequest)))
                    .andExpect(status().isForbidden())
                    .andReturn().getResponse().getContentAsString();

            assertThat(content).isNotNull();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse).isNotNull();
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/complete-auth");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
            assertThat(exceptionResponse.getMessage()).isEqualTo("User is blocked.");

            verify(userQueryPort).getByEmail(user.email());
            verify(userCommandPort, never()).update(anyString(), any(UpdateUserRequest.class));
        }

        @Test
        void completeProfile_shouldReturn_whenUserAlreadyCompletedRegistration() throws Exception {
            User user = UserDataBuilder.buildUserAllFields()
                    .emailVerified(true)
                    .status(UserStatus.ACTIVE)
                    .build();
            CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder.buildCompleteAuthRequestWithAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            String content = mockMvc.perform(patch("/auth/complete-auth")
                            .param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(completeAuthRequest)))
                    .andExpect(status().isConflict())
                    .andReturn().getResponse().getContentAsString();

            assertThat(content).isNotNull();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse).isNotNull();
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/complete-auth");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getErrors()).isNull();
            assertThat(exceptionResponse.getMessage()).isEqualTo("User account is already activated.");

            verify(userQueryPort).getByEmail(user.email());
            verify(userCommandPort, never()).update(anyString(), any(UpdateUserRequest.class));
        }
    }

    @Nested
    class AuthenticatedUserTests {

        @Test
        void getAuthenticatedUser_shouldReturnUserProfile() throws Exception {
            AuthUser authUser = AuthUserDataBuilder.buildAuthUserWithAllFields()
                    .status(UserStatus.ACTIVE)
                    .build();
            SecurityContext securityContext = initializeSecurityContext(authUser);

            when(securityContextHelper.getAuthenticatedUser()).thenReturn(authUser);

            String content = mockMvc.perform(get("/auth/me")
                            .contentType(MediaType.APPLICATION_JSON)
                            .with(SecurityMockMvcRequestPostProcessors.securityContext(securityContext)))
                    .andExpect(status().isOk())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotNull();
            UserProfileResponse responseDto = objectMapper.readValue(content, UserProfileResponse.class);

            assertThat(content).doesNotContain("password");
            assertThat(responseDto).isNotNull();
            assertThat(responseDto.id()).isEqualTo(authUser.id());
            assertThat(responseDto.email()).isEqualTo(authUser.email());
            assertThat(responseDto.fullName()).isEqualTo(authUser.fullName());
            assertThat(responseDto.role()).isEqualTo(authUser.role());
            assertThat(responseDto.status()).isEqualTo(authUser.status());
            assertThat(responseDto.providerType()).isEqualTo(authUser.providerType());
            assertThat(responseDto.createdAt()).isNotNull();
            assertThat(responseDto.updatedAt()).isNotNull();

            verify(securityContextHelper).getAuthenticatedUser();
        }

        @Test
        void getAuthenticatedUser_shouldReturnUnauthorized_whenNotUserInstance() throws Exception {
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    "not-a-user-object",
                    null,
                    null);
            SecurityContext securityContext = initializeSecurityContext(authToken);

            when(securityContextHelper.getAuthenticatedUser()).thenThrow(new AuthenticationCredentialsNotFoundException("Unauthorized."));

            String content = mockMvc.perform(get("/auth/me")
                            .contentType(MediaType.APPLICATION_JSON)
                            .with(SecurityMockMvcRequestPostProcessors.securityContext(securityContext)))
                    .andExpect(status().isUnauthorized())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse).isNotNull();
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/me");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
            assertThat(exceptionResponse.getMessage()).isEqualTo("Unauthorized.");

            verify(securityContextHelper).getAuthenticatedUser();
        }

        @Test
        void getAuthenticatedUser_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.buildUserAllFields()
                    .status(UserStatus.ACTIVE)
                    .build();
            String accessToken = "access_token";
            Claims mockedClaims = mock(Claims.class);

            when(jwtHelper.extractAllClaims(accessToken)).thenReturn(mockedClaims);
            when(mockedClaims.getSubject()).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenThrow(new UserNotFoundException("User not found."));

            String content = mockMvc.perform(get("/auth/me")
                            .header(AUTHORIZATION_HEADER, BEARER_PREFIX + accessToken)
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isNotFound())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse).isNotNull();
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/me");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
            assertThat(exceptionResponse.getMessage()).isEqualTo("User not found.");
        }
    }
}
