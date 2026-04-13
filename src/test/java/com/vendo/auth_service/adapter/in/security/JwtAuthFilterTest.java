package com.vendo.auth_service.adapter.in.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.auth_service.adapter.common.SecurityContextService;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.security.TokenClaimsParser;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.security_lib.exception.response.ExceptionResponse;
import com.vendo.user_lib.exception.UserNotFoundException;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import io.jsonwebtoken.ExpiredJwtException;
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

import static com.vendo.security_lib.constants.AuthConstants.BEARER_PREFIX;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
public class JwtAuthFilterTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private UserCommandPort userCommandPort;

    @MockitoBean
    private TokenClaimsParser tokenClaimsParser;

    @MockitoBean
    private UserQueryPort userQueryPort;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_shouldPassAuthorization_whenUserAlreadyAuthorized() throws Exception {
        SecurityContext securityContext = SecurityContextService.initializeSecurityContext(UserRole.USER);

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
        String accessToken = "access_token";

        when(tokenClaimsParser.extractSubject(accessToken)).thenReturn(user.email());
        when(userQueryPort.getByEmail(user.email())).thenReturn(user);

        mockMvc.perform(get("/test/ping").header(AUTHORIZATION, BEARER_PREFIX + accessToken))
                .andExpect(status().isOk());

        verify(tokenClaimsParser).extractSubject(accessToken);
        verify(userQueryPort).getByEmail(user.email());
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenWithoutBearerPrefix() throws Exception {
        String accessToken = "access_token";

        String content = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, accessToken))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(content).isNotBlank();

        ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);
        assertThat(exceptionResponse.getMessage()).isEqualTo("Invalid or expired token.");
        assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(exceptionResponse.getPath()).isEqualTo("/test/ping");
    }

    @Test
    void doFilterInternal_shouldReturnNotFound() throws Exception {
        User user = UserDataBuilder.buildUserAllFields().build();
        String accessToken = "access_token";

        when(tokenClaimsParser.extractSubject(accessToken)).thenReturn(user.email());
        when(userQueryPort.getByEmail(user.email())).thenThrow(new UserNotFoundException("User not found."));

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

        verify(tokenClaimsParser).extractSubject(accessToken);
        verify(userQueryPort).getByEmail(user.email());
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenTokenIsNotValid() throws Exception {
        String expiredToken = "access_token";

        when(tokenClaimsParser.extractSubject(expiredToken)).thenThrow(ExpiredJwtException.class);

        String content = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, BEARER_PREFIX + expiredToken))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(content).isNotBlank();
        ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);
        assertThat(exceptionResponse.getMessage()).isEqualTo("Invalid or expired token.");
        assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(exceptionResponse.getPath()).isEqualTo("/test/ping");

        verify(tokenClaimsParser).extractSubject(expiredToken);
        verify(userQueryPort, never()).getByEmail(anyString());
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenUserIsBlocked() throws Exception {
        User user = UserDataBuilder.buildUserAllFields()
                .status(UserStatus.BLOCKED)
                .emailVerified(true)
                .build();
        String accessToken = "access_token";

        when(tokenClaimsParser.extractSubject(accessToken)).thenReturn(user.email());
        when(userQueryPort.getByEmail(user.email())).thenReturn(user);

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

        verify(tokenClaimsParser).extractSubject(accessToken);
        verify(userQueryPort).getByEmail(user.email());
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenUserIsIncomplete() throws Exception {
        User user = UserDataBuilder.buildUserAllFields()
                .status(UserStatus.INCOMPLETE)
                .emailVerified(true)
                .build();
        String accessToken = "access_token";

        when(tokenClaimsParser.extractSubject(accessToken)).thenReturn(user.email());
        when(userQueryPort.getByEmail(user.email())).thenReturn(user);

        String response = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, BEARER_PREFIX + accessToken))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(response).isNotBlank();

        ExceptionResponse exceptionResponse = objectMapper.readValue(response, ExceptionResponse.class);
        assertThat(exceptionResponse.getMessage()).isEqualTo("User is unactive.");
        assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(exceptionResponse.getPath()).isEqualTo("/test/ping");

        verify(tokenClaimsParser).extractSubject(accessToken);
        verify(userQueryPort).getByEmail(user.email());
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenUserEmailIsNotVerified() throws Exception {
        User user = UserDataBuilder.buildUserAllFields()
                .emailVerified(false)
                .build();
        String accessToken = "access_token";

        when(tokenClaimsParser.extractSubject(accessToken)).thenReturn(user.email());
        when(userQueryPort.getByEmail(user.email())).thenReturn(user);

        String content = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, BEARER_PREFIX + accessToken))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(content).isNotBlank();

        ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);
        assertThat(exceptionResponse.getMessage()).isEqualTo("User email is not verified.");
        assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());

        verify(tokenClaimsParser).extractSubject(accessToken);
        verify(userQueryPort).getByEmail(user.email());
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorizedForEmailNotVerifiedFirst_whenUserEmailIsNotVerifiedAndStatusIsIncomplete() throws Exception {
        User user = UserDataBuilder.buildUserAllFields()
                .status(UserStatus.INCOMPLETE)
                .emailVerified(false)
                .build();
        String accessToken = "access_token";

        when(tokenClaimsParser.extractSubject(accessToken)).thenReturn(user.email());
        when(userQueryPort.getByEmail(user.email())).thenReturn(user);

        String content = mockMvc.perform(get("/test/ping").header(AUTHORIZATION, BEARER_PREFIX + accessToken))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(content).isNotBlank();

        ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);
        assertThat(exceptionResponse.getMessage()).isEqualTo("User email is not verified.");
        assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());

        verify(tokenClaimsParser).extractSubject(accessToken);
        verify(userQueryPort).getByEmail(user.email());
    }

}
