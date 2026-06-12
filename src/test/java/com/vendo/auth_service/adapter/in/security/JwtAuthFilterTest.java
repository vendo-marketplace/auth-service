package com.vendo.auth_service.adapter.in.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.auth_service.test_utils.SecurityContextService;
import com.vendo.auth_service.test_utils.dto.PingRequest;
import com.vendo.security_lib.exception.response.ExceptionResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
    void doFilterInternal_shouldPassFilter_whenUserAlreadyAuthorized() throws Exception {
        User user = UserDataBuilder.withAllFields().build();
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
    void doFilterInternal_shouldReturnUnsupportedMediaType_whenMediaTypeIsText() throws Exception {
        User user = UserDataBuilder.withAllFields().build();
        PingRequest request = new PingRequest("content");
        SecurityContext securityContext = SecurityContextService.initializeSecurityContext(user);

        String content = mockMvc.perform(post("/test/ping")
                        .content(objectMapper.writeValueAsString(request))
                        .contentType(MediaType.TEXT_PLAIN)
                        .with(securityContext(securityContext)))
                .andExpect(status().isUnsupportedMediaType())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(content).isNotBlank();
        ExceptionResponse exceptionResponse = objectMapper.readValue(content, ExceptionResponse.class);
        assertThat(exceptionResponse.getMessage()).isEqualTo("Unsupported media type.");
        assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.UNSUPPORTED_MEDIA_TYPE.value());
    }

    @Test
    void doFilterInternal_shouldPassFilter_whenHeadersAreValid() throws Exception {
        User user = UserDataBuilder.withAllFields().build();
        mockMvc.perform(get("/test/ping").headers(SecurityContextService.extractHeaders(user)))
                .andExpect(status().isOk());
    }

    @Test
    void doFilterInternal_shouldReturnUnauthorized_whenNoIdHeaderInRequest() throws Exception {
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
}
