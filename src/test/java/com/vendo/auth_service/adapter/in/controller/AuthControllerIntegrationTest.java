package com.vendo.auth_service.adapter.in.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.auth_service.adapter.auth.in.dto.AuthRequest;
import com.vendo.auth_service.adapter.auth.in.dto.CompleteAuthRequest;
import com.vendo.auth_service.adapter.auth.in.dto.RefreshRequest;
import com.vendo.auth_service.adapter.security.out.SecurityContextHelper;
import com.vendo.auth_service.adapter.user.in.dto.UserProfileResponse;
import com.vendo.auth_service.application.auth.dto.*;
import com.vendo.auth_service.domain.auth.dto.AuthRequestDataBuilder;
import com.vendo.auth_service.domain.auth.dto.CompleteAuthRequestDataBuilder;
import com.vendo.auth_service.domain.auth.dto.TokenPayloadDataBuilder;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.security.BearerTokenExtractor;
import com.vendo.auth_service.port.security.PasswordHashingPort;
import com.vendo.auth_service.port.security.TokenClaimsParser;
import com.vendo.auth_service.port.security.TokenGenerationService;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.security_lib.exception.response.ExceptionResponse;
import com.vendo.user_lib.exception.UserNotFoundException;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import com.vendo.utils_lib.AssertionUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDate;

import static com.vendo.auth_service.test_utils.SecurityContextService.initializeSecurityContext;
import static com.vendo.security_lib.constants.AuthConstants.BEARER_PREFIX;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private PasswordHashingPort passwordHashingPort;

    @MockitoBean
    private UserQueryPort userQueryPort;

    @MockitoBean
    private UserCommandPort userCommandPort;

    @MockitoBean
    private SecurityContextHelper securityContextHelper;

    @MockitoBean
    private TokenClaimsParser tokenClaimsParser;

    @MockitoBean
    private BearerTokenExtractor bearerTokenExtractor;

    @MockitoBean
    private TokenGenerationService tokenGenerationService;

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
            User user = UserDataBuilder.withAllFields()
                    .email(authRequest.email())
                    .build();
            SaveUserRequest request = SaveUserRequest.builder().build();

            String encodedPassword = "encoded_password";

            when(userQueryPort.existsByEmail(authRequest.email())).thenReturn(false);
            when(passwordHashingPort.hash(authRequest.password())).thenReturn(encodedPassword);
            when(userCommandPort.save(request)).thenReturn(user);

            mockMvc.perform(post("/auth/sign-up")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authRequest)))
                    .andExpect(status().isOk());

            ArgumentCaptor<SaveUserRequest> saveUserRequestArgumentCaptor = ArgumentCaptor.forClass(SaveUserRequest.class);
            verify(userQueryPort).existsByEmail(authRequest.email());
            verify(userCommandPort).save(saveUserRequestArgumentCaptor.capture());

            SaveUserRequest saveUserRequestCaptor = saveUserRequestArgumentCaptor.getValue();
            assertThat(saveUserRequestCaptor.email()).isEqualTo(authRequest.email());
            assertThat(saveUserRequestCaptor.password()).isEqualTo(encodedPassword);
            assertThat(saveUserRequestCaptor.role()).isEqualTo(UserRole.USER);
            assertThat(saveUserRequestCaptor.status()).isEqualTo(UserStatus.INCOMPLETE);
            assertThat(saveUserRequestCaptor.providerType()).isEqualTo(ProviderType.LOCAL);
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
            verify(passwordHashingPort, never()).hash(anyString());
            verify(userCommandPort, never()).save(any(SaveUserRequest.class));
        }
    }

    @Nested
    class SignInTests {

        @Test
        void signIn_shouldReturnPairOfTokens() throws Exception {
            AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();
            User user = UserDataBuilder.withAllFields()
                    .status(UserStatus.ACTIVE)
                    .email(authRequest.email())
                    .emailVerified(true)
                    .build();
            TokenPayload tokenPayload = TokenPayloadDataBuilder.buildTokenPayloadWithAllFields().build();

            when(userQueryPort.getByEmail(authRequest.email())).thenReturn(user);
            when(passwordHashingPort.matches(authRequest.password(), user.password())).thenReturn(true);
            when(tokenGenerationService.generate(user)).thenReturn(tokenPayload);

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
            verify(passwordHashingPort).matches(authRequest.password(), user.password());
            verify(tokenGenerationService).generate(user);
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
            verify(passwordHashingPort, never()).matches(anyString(), anyString());
            verify(tokenGenerationService, never()).generate(any(User.class));
        }

        @Test
        void signIn_shouldReturnForbidden_whenUserBlocked() throws Exception {
            AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();
            User user = UserDataBuilder.withAllFields()
                    .status(UserStatus.BLOCKED)
                    .email(authRequest.email())
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
            verify(passwordHashingPort, never()).matches(authRequest.password(), user.password());
            verify(tokenGenerationService, never()).generate(user);
        }

        @Test
        void signIn_shouldReturnForbidden_whenUserIncomplete() throws Exception {
            AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();
            User user = UserDataBuilder.withAllFields()
                    .status(UserStatus.INCOMPLETE)
                    .emailVerified(true)
                    .email(authRequest.email())
                    .build();

            when(userQueryPort.getByEmail(authRequest.email())).thenReturn(user);

            String content = mockMvc.perform(post("/auth/sign-in")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authRequest)))
                    .andExpect(status().isUnauthorized())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotBlank();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse.getMessage()).isEqualTo("User is unactive.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/sign-in");

            verify(userQueryPort).getByEmail(user.email());
            verify(passwordHashingPort, never()).matches(authRequest.password(), user.password());
            verify(tokenGenerationService, never()).generate(user);
        }

        @Test
        void signIn_shouldReturnForbidden_whenUserEmailIsNotVerified() throws Exception {
            AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();
            User user = UserDataBuilder.withAllFields()
                    .status(UserStatus.INCOMPLETE)
                    .emailVerified(false)
                    .email(authRequest.email())
                    .build();

            when(userQueryPort.getByEmail(authRequest.email())).thenReturn(user);

            String content = mockMvc.perform(post("/auth/sign-in")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authRequest)))
                    .andExpect(status().isUnauthorized())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotBlank();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse.getMessage()).isEqualTo("User email is not verified.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/sign-in");

            verify(userQueryPort).getByEmail(user.email());
            verify(passwordHashingPort, never()).matches(authRequest.password(), user.password());
            verify(tokenGenerationService, never()).generate(user);
        }
    }

    @Nested
    class RefreshTests {

        @Test
        void refresh_shouldReturnPairOfTokens() throws Exception {
            User user = UserDataBuilder.withAllFields().build();
            RefreshRequest refreshRequest = RefreshRequest.builder().refreshToken(BEARER_PREFIX + "refresh_token").build();
            TokenPayload tokenPayload = TokenPayloadDataBuilder.buildTokenPayloadWithAllFields().build();

            when(bearerTokenExtractor.extract(refreshRequest.refreshToken())).thenReturn(refreshRequest.refreshToken());
            when(tokenClaimsParser.extractSubject(refreshRequest.refreshToken())).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            when(tokenGenerationService.generate(user)).thenReturn(tokenPayload);

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

            verify(bearerTokenExtractor).extract(refreshRequest.refreshToken());
            verify(tokenClaimsParser).extractSubject(refreshRequest.refreshToken());
            verify(userQueryPort).getByEmail(user.email());
            verify(tokenGenerationService).generate(user);
        }

        @Test
        void refresh_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.withAllFields().build();
            RefreshRequest refreshRequest = RefreshRequest.builder().refreshToken(BEARER_PREFIX + "refresh_token").build();

            when(bearerTokenExtractor.extract(refreshRequest.refreshToken())).thenReturn(refreshRequest.refreshToken());
            when(tokenClaimsParser.extractSubject(refreshRequest.refreshToken())).thenReturn(user.email());
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

            verify(bearerTokenExtractor).extract(refreshRequest.refreshToken());
            verify(tokenClaimsParser).extractSubject(refreshRequest.refreshToken());
            verify(userQueryPort).getByEmail(user.email());
            verify(tokenGenerationService, never()).generate(user);
        }

        @Test
        void refresh_shouldReturnUnauthorized_whenTokenWithoutBearerPrefix() throws Exception {
            RefreshRequest refreshRequest = RefreshRequest.builder().refreshToken("refresh_token").build();

            when(bearerTokenExtractor.extract(refreshRequest.refreshToken())).thenThrow(new BadCredentialsException("Invalid or expired token."));

            String content = mockMvc.perform(post("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(refreshRequest)))
                    .andExpect(status().isUnauthorized())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotBlank();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse.getMessage()).isEqualTo("Invalid or expired token.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/refresh");

            verify(bearerTokenExtractor).extract(refreshRequest.refreshToken());
            verify(tokenClaimsParser, never()).extractSubject(anyString());
            verify(userQueryPort, never()).getByEmail(anyString());
            verify(tokenGenerationService, never()).generate(any(User.class));
        }

        @Test
        void refresh_shouldReturnUnauthorized_whenTokenIsExpired() throws Exception {
            RefreshRequest refreshRequest = RefreshRequest.builder().refreshToken(BEARER_PREFIX + "refresh_token").build();

            when(bearerTokenExtractor.extract(refreshRequest.refreshToken())).thenReturn(refreshRequest.refreshToken());
            when(tokenClaimsParser.extractSubject(refreshRequest.refreshToken())).thenThrow(new BadCredentialsException("Invalid or expired token."));

            String content = mockMvc.perform(post("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(refreshRequest)))
                    .andExpect(status().isUnauthorized())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotBlank();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse.getMessage()).isEqualTo("Invalid or expired token.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/refresh");

            verify(bearerTokenExtractor).extract(refreshRequest.refreshToken());
            verify(tokenClaimsParser).extractSubject(refreshRequest.refreshToken());
            verify(userQueryPort, never()).getByEmail(anyString());
            verify(tokenGenerationService, never()).generate(any(User.class));
        }
    }

    @Nested
    class CompleteTests {

        @Test
        void complete_shouldSuccessfullyCompleteRegistration() throws Exception {
            CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder.buildCompleteAuthRequestWithAllFields().build();
            ArgumentCaptor<UpdateUserRequest> updateUserArgumentCaptor = ArgumentCaptor.forClass(UpdateUserRequest.class);

            SecurityContext securityContext = initializeSecurityContext(UserRole.USER);
            User authUser = UserDataBuilder.withAllFields()
                    .status(UserStatus.INCOMPLETE)
                    .emailVerified(true)
                    .build();

            when(securityContextHelper.getAuthUser()).thenReturn(authUser);
            doNothing().when(userCommandPort).update(eq(authUser.id()), updateUserArgumentCaptor.capture());

            mockMvc.perform(patch("/auth/complete")
                            .with(SecurityMockMvcRequestPostProcessors.securityContext(securityContext))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(completeAuthRequest)))
                    .andExpect(status().isOk());

            UpdateUserRequest updateUserArgumentCaptorValue = updateUserArgumentCaptor.getValue();
            verify(userCommandPort).update(authUser.id(), updateUserArgumentCaptorValue);
            verifyNoInteractions(userQueryPort);

            assertThat(updateUserArgumentCaptorValue).isNotNull();
            assertThat(updateUserArgumentCaptorValue.status()).isEqualTo(UserStatus.ACTIVE);
            assertThat(updateUserArgumentCaptorValue.fullName()).isEqualTo(completeAuthRequest.fullName());
            assertThat(updateUserArgumentCaptorValue.birthDate()).isEqualTo(completeAuthRequest.birthDate());
        }

        @Test
        void complete_shouldReturnBadRequest_whenNotValidFullName() throws Exception {
            CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder
                    .buildCompleteAuthRequestWithAllFields()
                    .fullName("Invalid_fullName")
                    .build();
            SecurityContext securityContext = initializeSecurityContext(UserRole.USER);

            String content = mockMvc.perform(patch("/auth/complete")
                            .with(SecurityMockMvcRequestPostProcessors.securityContext(securityContext))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(completeAuthRequest)))
                    .andExpect(status().isBadRequest())
                    .andReturn().getResponse().getContentAsString();

            assertThat(content).isNotNull();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse).isNotNull();
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/complete");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
            assertThat(exceptionResponse.getErrors()).isNotNull();
            assertThat(exceptionResponse.getErrors().size()).isEqualTo(1);
            assertThat(exceptionResponse.getErrors().get("fullName")).isNotNull();
        }

        @Test
        void complete_shouldReturnBadRequest_whenNotAdult() throws Exception {
            CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder
                    .buildCompleteAuthRequestWithAllFields()
                    .birthDate(LocalDate.now())
                    .build();
            SecurityContext securityContext = initializeSecurityContext(UserRole.USER);

            String content = mockMvc.perform(patch("/auth/complete")
                            .with(SecurityMockMvcRequestPostProcessors.securityContext(securityContext))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(completeAuthRequest)))
                    .andExpect(status().isBadRequest())
                    .andReturn().getResponse().getContentAsString();

            assertThat(content).isNotNull();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse).isNotNull();
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/complete");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
            assertThat(exceptionResponse.getErrors()).isNotNull();
            assertThat(exceptionResponse.getErrors().size()).isEqualTo(1);
            assertThat(exceptionResponse.getErrors().get("birthDate")).isNotNull();
        }

        @Test
        void complete_shouldReturnBadRequest_whenBothNotAdultAndInvalidFullName() throws Exception {
            CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder
                    .buildCompleteAuthRequestWithAllFields()
                    .fullName("Invalid_fullName")
                    .birthDate(LocalDate.of(2025, 1, 1))
                    .build();
            SecurityContext securityContext = initializeSecurityContext(UserRole.USER);

            String content = mockMvc.perform(patch("/auth/complete")
                            .with(SecurityMockMvcRequestPostProcessors.securityContext(securityContext))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(completeAuthRequest)))
                    .andExpect(status().isBadRequest())
                    .andReturn().getResponse().getContentAsString();

            assertThat(content).isNotNull();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse).isNotNull();
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/complete");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
            assertThat(exceptionResponse.getErrors()).isNotNull();
            assertThat(exceptionResponse.getErrors().size()).isEqualTo(2);
            assertThat(exceptionResponse.getErrors().get("birthDate")).isNotNull();
            assertThat(exceptionResponse.getErrors().get("fullName")).isNotNull();
        }

        @Test
        void complete_shouldReturnNotFound_whenUserNotFound() throws Exception {
            CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder
                    .buildCompleteAuthRequestWithAllFields().build();
            SecurityContext securityContext = initializeSecurityContext(UserRole.USER);
            User authUser = UserDataBuilder.withAllFields()
                    .status(UserStatus.INCOMPLETE)
                    .build();

            when(securityContextHelper.getAuthUser()).thenReturn(authUser);
            doThrow(new UserNotFoundException("User not found."))
                    .when(userCommandPort).update(eq(authUser.id()), any(UpdateUserRequest.class));

            String content = mockMvc.perform(patch("/auth/complete")
                            .with(SecurityMockMvcRequestPostProcessors.securityContext(securityContext))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(completeAuthRequest)))
                    .andExpect(status().isNotFound())
                    .andReturn().getResponse().getContentAsString();

            assertThat(content).isNotNull();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse).isNotNull();
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/complete");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
            assertThat(exceptionResponse.getMessage()).isEqualTo("User not found.");

            verifyNoInteractions(userQueryPort);
            verify(userCommandPort).update(eq(authUser.id()), any(UpdateUserRequest.class));
        }

        @Test
        void complete_shouldReturnForbidden_whenUserBlocked() throws Exception {
            CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder
                    .buildCompleteAuthRequestWithAllFields().build();
            SecurityContext securityContext = initializeSecurityContext(UserRole.USER);
            User authUser = UserDataBuilder.withAllFields()
                    .status(UserStatus.BLOCKED)
                    .build();

            when(securityContextHelper.getAuthUser()).thenReturn(authUser);

            String content = mockMvc.perform(patch("/auth/complete")
                            .with(SecurityMockMvcRequestPostProcessors.securityContext(securityContext))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(completeAuthRequest)))
                    .andExpect(status().isForbidden())
                    .andReturn().getResponse().getContentAsString();

            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse).isNotNull();
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/complete");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
            assertThat(exceptionResponse.getMessage()).isEqualTo("User is blocked.");

            verify(userCommandPort, never()).update(anyString(), any(UpdateUserRequest.class));
        }

        @Test
        void complete_shouldReturnForbidden_whenUserEmailNotVerified() throws Exception {
            CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder
                    .buildCompleteAuthRequestWithAllFields().build();
            SecurityContext securityContext = initializeSecurityContext(UserRole.USER);
            User authUser = UserDataBuilder.withAllFields()
                    .status(UserStatus.INCOMPLETE)
                    .emailVerified(false)
                    .build();

            when(securityContextHelper.getAuthUser()).thenReturn(authUser);

            String content = mockMvc.perform(patch("/auth/complete")
                            .with(SecurityMockMvcRequestPostProcessors.securityContext(securityContext))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(completeAuthRequest)))
                    .andExpect(status().isUnauthorized())
                    .andReturn().getResponse().getContentAsString();

            assertThat(content).isNotNull();
            ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);

            assertThat(exceptionResponse).isNotNull();
            assertThat(exceptionResponse.getPath()).isEqualTo("/auth/complete");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
            assertThat(exceptionResponse.getMessage()).isEqualTo("User email is not verified.");

            verify(userCommandPort, never()).update(anyString(), any(UpdateUserRequest.class));
        }
    }

    @Nested
    class AuthenticatedUserTests {

        @Test
        void getAuthenticatedUser_shouldReturnUserProfile() throws Exception {
            User authUser = UserDataBuilder.withAllFields()
                    .status(UserStatus.ACTIVE)
                    .build();

            SecurityContext securityContext = initializeSecurityContext(authUser);

            when(securityContextHelper.getAuthUser()).thenReturn(authUser);

            String content = mockMvc.perform(get("/auth/me")
                            .contentType(MediaType.APPLICATION_JSON)
                            .with(SecurityMockMvcRequestPostProcessors.securityContext(securityContext)))
                    .andExpect(status().isOk())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(content).isNotNull();
            UserProfileResponse responseDto = objectMapper.readValue(content, UserProfileResponse.class);

            AssertionUtils.assertFrom(authUser, responseDto, "createdAt", "updatedAt");

            assertThat(content).doesNotContain("password");
            assertThat(responseDto.createdAt()).isNotNull();
            assertThat(responseDto.updatedAt()).isNotNull();

            verify(securityContextHelper).getAuthUser();
        }

        @Test
        void getAuthenticatedUser_shouldReturnUnauthorized_whenNotUserInstance() throws Exception {
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    "not-a-user-object",
                    null,
                    null);
            SecurityContext securityContext = initializeSecurityContext(authToken);

            when(securityContextHelper.getAuthUser()).thenThrow(new AuthenticationCredentialsNotFoundException("Unauthorized."));

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

            verify(securityContextHelper).getAuthUser();
        }
    }
}
