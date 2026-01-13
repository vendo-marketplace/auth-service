package com.vendo.auth_service.adapter.out.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.auth_service.domain.user.dto.SaveUserRequestDataBuilder;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.common.dto.SaveUserRequest;
import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.common.exception.ExceptionResponse;
import com.vendo.domain.user.common.type.UserStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static com.vendo.security.common.constants.AuthConstants.BEARER_PREFIX;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
public class JwtAuthFilterIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TestJwtService testJwtService;

    @MockitoBean
    private UserCommandPort userCommandPort;

    @MockitoBean
    private UserQueryPort userQueryPort;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        userCommandPort.deleteAll();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        userCommandPort.deleteAll();
    }

    @Test
    void doFilterInternal_shouldPassAuthorization_whenUserAlreadyAuthorized() throws Exception {
        User user = UserDataBuilder.buildUserAllFields().build();
        SecurityContext securityContext = SecurityContextService.initializeSecurityContext(user);

        String content = mockMvc.perform(get("/test/ping")
                        .with(securityContext(securityContext)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(content).isNotBlank();
        assertThat(content).isEqualTo("pong");
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenNoTokenInRequest() throws Exception {
        String content = mockMvc.perform(get("/test/ping"))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(content).isNotBlank();

        ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);
        assertThat(exceptionResponse.getMessage()).isEqualTo("Unauthorized.");
        assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void doFilterInternal_shouldPassFilter_whenTokenIsValid() throws Exception {
        User user = UserDataBuilder.buildUserAllFields()
                .status(UserStatus.ACTIVE)
                .emailVerified(true)
                .build();
        SaveUserRequest saveUserRequest = SaveUserRequest.builder().build();

        userCommandPort.save(saveUserRequest);
        String accessToken = testJwtService.generateAccessToken(user);

        mockMvc.perform(get("/test/ping").header(AUTHORIZATION, BEARER_PREFIX + accessToken))
                .andExpect(status().isOk());
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenWithoutBearerPrefix() throws Exception {
        User user = UserDataBuilder.buildUserAllFields().build();
        String accessToken = testJwtService.generateAccessToken(user);

        String content = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, accessToken))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(content).isNotBlank();

        ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);
        assertThat(exceptionResponse.getMessage()).isEqualTo("Invalid token.");
        assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(exceptionResponse.getPath()).isEqualTo("/test/ping");
    }

    @Test
    void doFilterInternal_shouldReturnNotFound_whenUserNotFound() throws Exception {
        User user = UserDataBuilder.buildUserAllFields().build();
        String accessToken = testJwtService.generateAccessToken(user);

        String content = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, BEARER_PREFIX + accessToken))
                .andExpect(status().isNotFound())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(content).isNotBlank();

        ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);
        assertThat(exceptionResponse.getMessage()).isEqualTo("User not found.");
        assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
        assertThat(exceptionResponse.getPath()).isEqualTo("/test/ping");
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenIsNotValid() throws Exception {
        SaveUserRequest saveUserRequest = SaveUserRequestDataBuilder.buildWithAllFields().build();
        User user = UserDataBuilder.buildUserAllFields()
                .email(saveUserRequest.email())
                .build();

        userCommandPort.save(saveUserRequest);
        String expiredToken = testJwtService.generateTokenWithExpiration(user, 0);

        String content = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, BEARER_PREFIX + expiredToken))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse()
                .getContentAsString();


        assertThat(content).isNotBlank();

        ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);
        assertThat(exceptionResponse.getMessage()).isEqualTo("Token has expired.");
        assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(exceptionResponse.getPath()).isEqualTo("/test/ping");
    }

    @Test
    void doFilterInternal_shouldReturnForbidden_whenUserIsBlocked() throws Exception {
        SaveUserRequest saveUserRequest = SaveUserRequestDataBuilder.buildWithAllFields()
                .status(UserStatus.BLOCKED)
                .build();
        User user = UserDataBuilder.buildUserAllFields()
                .email(saveUserRequest.email())
                .status(UserStatus.BLOCKED)
                .emailVerified(true)
                .build();

        userCommandPort.save(saveUserRequest);
        String accessToken = testJwtService.generateAccessToken(user);

        String response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, BEARER_PREFIX + accessToken))
                .andExpect(status().isForbidden())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(response).isNotBlank();

        ExceptionResponse exceptionResponse = objectMapper.readValue(response, ExceptionResponse.class);
        assertThat(exceptionResponse.getMessage()).isEqualTo("User is blocked.");
        assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(exceptionResponse.getPath()).isEqualTo("/test/ping");
    }

    @Test
    void doFilterInternal_shouldReturnForbidden_whenUserIsIncomplete() throws Exception {
        SaveUserRequest saveUserRequest = SaveUserRequestDataBuilder.buildWithAllFields()
                .status(UserStatus.INCOMPLETE)
                .build();
        User user = UserDataBuilder.buildUserAllFields()
                .email(saveUserRequest.email())
                .status(UserStatus.INCOMPLETE)
                .emailVerified(true)
                .build();

        userCommandPort.save(saveUserRequest);
        String accessToken = testJwtService.generateAccessToken(user);

        String response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, BEARER_PREFIX + accessToken))
                .andExpect(status().isForbidden())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(response).isNotBlank();

        ExceptionResponse exceptionResponse = objectMapper.readValue(response, ExceptionResponse.class);
        assertThat(exceptionResponse.getMessage()).isEqualTo("User is unactive.");
        assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(exceptionResponse.getPath()).isEqualTo("/test/ping");
    }

    @Test
    void doFilterInternal_shouldReturnForbidden_whenUserEmailIsNotVerified() throws Exception {
        SaveUserRequest saveUserRequest = SaveUserRequestDataBuilder.buildWithAllFields()
                .build();
        User user = UserDataBuilder.buildUserAllFields()
                .email(saveUserRequest.email())
                .status(UserStatus.ACTIVE)
                .emailVerified(true)
                .build();

        userCommandPort.save(saveUserRequest);
        String accessToken = testJwtService.generateAccessToken(user);

        String content = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, BEARER_PREFIX + accessToken))
                .andExpect(status().isForbidden())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(content).isNotBlank();

        ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);
        assertThat(exceptionResponse.getMessage()).isEqualTo("User email is not verified.");
        assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
    }

    @Test
    void doFilterInternal_shouldReturnForbiddenForEmailNotVerifiedFirst_whenUserEmailIsNotVerifiedAndStatusIsIncomplete() throws Exception {
        SaveUserRequest saveUserRequest = SaveUserRequestDataBuilder.buildWithAllFields()
                .build();
        User user = UserDataBuilder.buildUserAllFields().email(saveUserRequest.email()).build();

        userCommandPort.save(saveUserRequest);
        String accessToken = testJwtService.generateAccessToken(user);

        String content = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, BEARER_PREFIX + accessToken))
                .andExpect(status().isForbidden())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(content).isNotBlank();

        ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);
        assertThat(exceptionResponse.getMessage()).isEqualTo("User email is not verified.");
        assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
    }
}
