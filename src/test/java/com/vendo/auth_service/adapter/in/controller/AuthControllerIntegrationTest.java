package com.vendo.auth_service.adapter.in.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.auth_service.adapter.common.TestJwtService;
import com.vendo.auth_service.adapter.in.security.dto.AuthUser;
import com.vendo.auth_service.adapter.in.web.dto.*;
import com.vendo.auth_service.adapter.out.security.helper.JwtHelper;
import com.vendo.auth_service.domain.auth.dto.AuthRequestDataBuilder;
import com.vendo.auth_service.domain.auth.dto.AuthUserDataBuilder;
import com.vendo.auth_service.domain.auth.dto.CompleteAuthRequestDataBuilder;
import com.vendo.auth_service.domain.user.common.dto.SaveUserRequest;
import com.vendo.auth_service.domain.user.common.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.auth_service.domain.user.common.exception.UserNotFoundException;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.port.security.TokenGenerationService;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.common.exception.ExceptionResponse;
import com.vendo.domain.user.common.type.UserRole;
import com.vendo.domain.user.common.type.UserStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
    private UserQueryPort userQueryPort;

    @MockitoBean
    private UserCommandPort userCommandPort;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TestJwtService testJwtService;

    @Autowired
    private TokenGenerationService tokenGenerationService;

    @Autowired
    private JwtHelper jwtHelper;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void signUp_shouldSuccessfullyRegisterUser() throws Exception {
        AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();

        Mockito.when(userQueryPort.existsByEmail(authRequest.email())).thenReturn(false);

        mockMvc.perform(post("/auth/sign-up")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk());

        ArgumentCaptor<SaveUserRequest> argumentCaptor = ArgumentCaptor.forClass(SaveUserRequest.class);

        Mockito.verify(userQueryPort).existsByEmail(authRequest.email());
        Mockito.verify(userCommandPort).save(argumentCaptor.capture());

        SaveUserRequest saveUserRequest = argumentCaptor.getValue();
        assertThat(saveUserRequest.email()).isEqualTo(authRequest.email());
        assertThat(saveUserRequest.role()).isEqualTo(UserRole.USER);
        assertThat(saveUserRequest.status()).isEqualTo(UserStatus.INCOMPLETE);
        assertThat(saveUserRequest.emailVerified()).isFalse();
        assertThat(passwordEncoder.matches(authRequest.password(), saveUserRequest.password())).isTrue();
    }

    @Test
    void signUp_shouldReturnConflict_whenUserAlreadyExists() throws Exception {
        AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();

        Mockito.when(userQueryPort.existsByEmail(authRequest.email())).thenReturn(true);

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
    }

    @Test
    void signIn_shouldReturnPairOfTokens() throws Exception {
        AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();

        User user = UserDataBuilder.buildUserAllFields()
                .status(UserStatus.ACTIVE)
                .email(authRequest.email())
                .emailVerified(true)
                .password(passwordEncoder.encode(authRequest.password()))
                .build();

        Mockito.when(userQueryPort.getByEmail(authRequest.email())).thenReturn(user);

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
        assertThat(jwtHelper.extractAllClaims(authResponse.accessToken())).isNotNull();

        assertThat(authResponse.refreshToken()).isNotBlank();
        assertThat(jwtHelper.extractAllClaims(authResponse.accessToken())).isNotNull();
    }

    @Test
    void signIn_shouldReturnNotFound_whenUserNotFound() throws Exception {
        AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();

        Mockito.when(userQueryPort.getByEmail(authRequest.email())).thenThrow(new UserNotFoundException("User not found."));

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
    }

    @Test
    void signIn_shouldReturnForbidden_whenUserBlocked() throws Exception {
        AuthRequest authRequest = AuthRequestDataBuilder.buildUserWithAllFields().build();
        User user = UserDataBuilder.buildUserAllFields()
                .status(UserStatus.BLOCKED)
                .email(authRequest.email())
                .password(passwordEncoder.encode(authRequest.password()))
                .build();

        Mockito.when(userQueryPort.getByEmail(authRequest.email())).thenReturn(user);

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

        Mockito.when(userQueryPort.getByEmail(authRequest.email())).thenReturn(user);

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

        Mockito.when(userQueryPort.getByEmail(authRequest.email())).thenReturn(user);

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
    }

    @Test
    void refresh_shouldReturnPairOfTokens() throws Exception {
        User user = UserDataBuilder.buildUserAllFields().build();
        String refreshToken = tokenGenerationService.generateTokensPair(user).refreshToken();
        RefreshRequest refreshRequest = RefreshRequest.builder().refreshToken(BEARER_PREFIX + refreshToken).build();

        Mockito.when(userQueryPort.getByEmail(user.email())).thenReturn(user);

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
        assertThat(jwtHelper.extractAllClaims(authResponse.accessToken())).isNotNull();

        assertThat(authResponse.refreshToken()).isNotBlank();
        assertThat(jwtHelper.extractAllClaims(authResponse.accessToken())).isNotNull();
    }

    @Test
    void refresh_shouldReturnNotFound_whenUserNotFound() throws Exception {
        User user = UserDataBuilder.buildUserAllFields().build();
        String refreshToken = tokenGenerationService.generateTokensPair(user).refreshToken();
        RefreshRequest refreshRequest = RefreshRequest.builder().refreshToken(BEARER_PREFIX + refreshToken).build();

        Mockito.when(userQueryPort.getByEmail(user.email())).thenThrow(new UserNotFoundException("User not found."));

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
    }

    @Test
    void refresh_shouldReturnUnauthorized_whenTokenWithoutBearerPrefix() throws Exception {
        User user = UserDataBuilder.buildUserAllFields().build();
        String refreshToken = tokenGenerationService.generateTokensPair(user).refreshToken();
        refreshToken = refreshToken.substring(BEARER_PREFIX.length() + 1);

        RefreshRequest refreshRequest = RefreshRequest.builder().refreshToken(refreshToken).build();

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
    }

    @Test
    void refresh_shouldReturnUnauthorized_whenTokenIsExpired() throws Exception {
        User user = UserDataBuilder.buildUserAllFields().build();
        String expiredRefreshToken = testJwtService.generateTokenWithExpiration(user, 0);
        RefreshRequest refreshRequest = RefreshRequest.builder().refreshToken(BEARER_PREFIX + expiredRefreshToken).build();

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
    }

    @Test
    void completeAuth_shouldSuccessfullyCompleteRegistration() throws Exception {
        User user = UserDataBuilder.buildUserAllFields().emailVerified(true).build();
        CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder.buildCompleteAuthRequestWithAllFields().build();

        Mockito.when(userQueryPort.getByEmail(user.email())).thenReturn(user);

        mockMvc.perform(patch("/auth/complete-auth")
                        .param("email", user.email())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(completeAuthRequest)))
                .andExpect(status().isOk());

        ArgumentCaptor<UpdateUserRequest> argumentCaptor = ArgumentCaptor.forClass(UpdateUserRequest.class);

        Mockito.verify(userQueryPort).getByEmail(user.email());
        Mockito.verify(userCommandPort).update(Mockito.eq(user.id()), argumentCaptor.capture());

        UpdateUserRequest updateUserRequest = argumentCaptor.getValue();
        assertThat(updateUserRequest).isNotNull();
        assertThat(updateUserRequest.status()).isEqualTo(UserStatus.ACTIVE);
        assertThat(updateUserRequest.fullName()).isEqualTo(completeAuthRequest.fullName());
        assertThat(updateUserRequest.birthDate()).isEqualTo(completeAuthRequest.birthDate());
    }

    @Test
    void completeProfile_shouldReturnBadRequest_whenNotValidFullName() throws Exception {
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
    void completeProfile_shouldReturnBadRequest_whenNotAdult() throws Exception {
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
    void completeProfile_shouldReturnBadRequest_whenBothNotAdultAndInvalidFullName() throws Exception {
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
    void completeProfile_shouldReturnNotFound_whenUserNotFound() throws Exception {
        User user = UserDataBuilder.buildUserAllFields().build();
        CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder.buildCompleteAuthRequestWithAllFields().build();

        Mockito.when(userQueryPort.getByEmail(user.email())).thenThrow(new UserNotFoundException("User not found."));

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
    }

    @Test
    void completeProfile_shouldReturnForbidden_whenUserBlocked() throws Exception {
        User user = UserDataBuilder.buildUserAllFields()
                .status(UserStatus.BLOCKED)
                .emailVerified(true)
                .build();

        CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder.buildCompleteAuthRequestWithAllFields().build();

        Mockito.when(userQueryPort.getByEmail(user.email())).thenReturn(user);

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
    }

    @Test
    void completeProfile_shouldReturn_whenUserAlreadyCompletedRegistration() throws Exception {
        User user = UserDataBuilder.buildUserAllFields()
                .emailVerified(true)
                .status(UserStatus.ACTIVE)
                .build();

        CompleteAuthRequest completeAuthRequest = CompleteAuthRequestDataBuilder.buildCompleteAuthRequestWithAllFields().build();

        Mockito.when(userQueryPort.getByEmail(user.email())).thenReturn(user);

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
    }

    @Test
    void getAuthenticatedUser_shouldReturnUserProfile() throws Exception {
        User user = UserDataBuilder.buildUserAllFields()
                .status(UserStatus.ACTIVE)
                .build();
        AuthUser authUser = AuthUserDataBuilder.buildAuthUserWithAllFields().status(UserStatus.ACTIVE).build();
        SecurityContext securityContext = initializeSecurityContext(authUser);

        Mockito.when(userQueryPort.getByEmail(user.email())).thenReturn(user);

        String content = mockMvc.perform(get("/auth/me")
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(SecurityMockMvcRequestPostProcessors.securityContext(securityContext)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
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
    }

    @Test
    void getAuthenticatedUser_shouldReturnUnauthorized_whenNotAuthUserInstance() throws Exception {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                "not-a-user-object",
                null,
                null);
        SecurityContext securityContext = initializeSecurityContext(authToken);

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
    }

    @Test
    void getAuthenticatedUser_shouldReturnNotFound_whenUserNotFound() throws Exception {
        User user = UserDataBuilder.buildUserAllFields()
                .status(UserStatus.ACTIVE)
                .build();

        String accessToken = testJwtService.generateAccessToken(user);

        Mockito.when(userQueryPort.getByEmail(user.email())).thenThrow(new UserNotFoundException("User not found."));

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
