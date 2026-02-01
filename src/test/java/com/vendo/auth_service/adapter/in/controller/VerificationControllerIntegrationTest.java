package com.vendo.auth_service.adapter.in.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.auth_service.application.otp.EmailOtpService;
import com.vendo.auth_service.application.otp.common.exception.InvalidOtpException;
import com.vendo.auth_service.application.otp.common.exception.OtpAlreadySentException;
import com.vendo.auth_service.application.otp.common.exception.TooManyOtpRequestsException;
import com.vendo.auth_service.domain.user.common.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.auth_service.domain.user.common.exception.UserNotFoundException;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.auth_service.adapter.out.db.redis.common.dto.ValidateRequest;
import com.vendo.auth_service.adapter.out.db.redis.common.namespace.otp.EmailVerificationOtpNamespace;
import com.vendo.common.exception.ExceptionResponse;
import com.vendo.integration.kafka.event.EmailOtpEvent;
import com.vendo.integration.redis.common.exception.OtpExpiredException;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.kafka.test.context.EmbeddedKafka;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.mockito.Mockito.*;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@EmbeddedKafka
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class VerificationControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private UserQueryPort userQueryPort;

    @MockitoBean
    private UserCommandPort userCommandPort;

    @MockitoBean
    private EmailOtpService emailOtpService;

    @Nested
    class SendOtpTests {

        @Test
        void sendOtp_shouldSendEmailVerificationEventSuccessfully() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            mockMvc.perform(MockMvcRequestBuilders.post("/verification/send-otp").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            ArgumentCaptor<EmailOtpEvent> emailOtpEventArgumentCaptor = ArgumentCaptor.forClass(EmailOtpEvent.class);
            verify(userQueryPort).getByEmail(user.email());
            verify(emailOtpService).sendOtp(emailOtpEventArgumentCaptor.capture(), any(EmailVerificationOtpNamespace.class));

            EmailOtpEvent emailOtpEvent = emailOtpEventArgumentCaptor.getValue();
            assertThat(emailOtpEvent).isNotNull();
            assertThat(emailOtpEvent.getOtp()).isNull();
            assertThat(emailOtpEvent.getEmail()).isEqualTo(user.email());
            assertThat(emailOtpEvent.getOtpEventType()).isEqualTo(EmailOtpEvent.OtpEventType.EMAIL_VERIFICATION);
        }

        @Test
        void sendOtp_shouldReturnConflict_whenEmailVerificationEventHasAlreadySent() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();

            ArgumentCaptor<EmailOtpEvent> emailOtpEventArgumentCaptor = ArgumentCaptor.forClass(EmailOtpEvent.class);
            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            doThrow(new OtpAlreadySentException("Otp has already sent."))
                    .when(emailOtpService)
                    .sendOtp(emailOtpEventArgumentCaptor.capture(), any(EmailVerificationOtpNamespace.class));

            String responseContent = mockMvc.perform(post("/verification/send-otp")
                            .contentType(MediaType.APPLICATION_JSON).param("email", user.email()))
                    .andExpect(status().isConflict())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Otp has already sent.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/send-otp");

            EmailOtpEvent emailOtpEvent = emailOtpEventArgumentCaptor.getValue();
            assertThat(emailOtpEvent).isNotNull();
            assertThat(emailOtpEvent.getOtp()).isNull();
            assertThat(emailOtpEvent.getEmail()).isEqualTo(user.email());
            assertThat(emailOtpEvent.getOtpEventType()).isEqualTo(EmailOtpEvent.OtpEventType.EMAIL_VERIFICATION);

            verify(userQueryPort).getByEmail(user.email());
            verify(emailOtpService).sendOtp(eq(emailOtpEvent), any(EmailVerificationOtpNamespace.class));
        }

        @Test
        void sendOtp_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenThrow(new UserNotFoundException("User not found."));

            String responseContent = mockMvc.perform(post("/verification/send-otp")
                            .contentType(MediaType.APPLICATION_JSON).param("email", user.email()))
                    .andExpect(status().isNotFound())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("User not found.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/send-otp");

            verify(userQueryPort).getByEmail(user.email());
            verify(emailOtpService, never()).sendOtp(any(EmailOtpEvent.class), any(EmailVerificationOtpNamespace.class));
        }
    }

    @Nested
    class ResendOtpTests {

        @Test
        void resendOtp_shouldSuccessfullyResendOtp() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            mockMvc.perform(post("/verification/resend-otp").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            verify(userQueryPort).getByEmail(user.email());
            verify(emailOtpService).resendOtp(any(EmailOtpEvent.class), any(EmailVerificationOtpNamespace.class));
        }

        @Test
        void resendOtp_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenThrow(new UserNotFoundException("User not found."));

            String responseContent = mockMvc.perform(post("/verification/resend-otp").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isNotFound())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("User not found.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/resend-otp");

            verify(userQueryPort).getByEmail(user.email());
            verify(emailOtpService, never()).resendOtp(any(EmailOtpEvent.class), any(EmailVerificationOtpNamespace.class));
        }

        @Test
        void resendOtp_shouldReturnTooManyRequests_whenTooManyAttempts() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            doThrow(new TooManyOtpRequestsException("Reached maximum attempts."))
                    .when(emailOtpService)
                    .resendOtp(any(EmailOtpEvent.class), any(EmailVerificationOtpNamespace.class));

            String responseContent = mockMvc.perform(post("/verification/resend-otp").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isTooManyRequests())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Reached maximum attempts.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/resend-otp");

            verify(userQueryPort).getByEmail(user.email());
            verify(emailOtpService).resendOtp(any(EmailOtpEvent.class), any(EmailVerificationOtpNamespace.class));
        }

        @Test
        void resendOtp_shouldReturnGone_whenOtpSessionExpired() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            doThrow(new OtpExpiredException("Otp session expired."))
                    .when(emailOtpService)
                    .resendOtp(any(EmailOtpEvent.class), any(EmailVerificationOtpNamespace.class));


            String responseContent = mockMvc.perform(post("/verification/resend-otp").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isGone())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Otp session expired.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.GONE.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/resend-otp");
        }
    }

    @Nested
    class ValidateTests {

        @Test
        void validate_shouldVerifyUser_whenOtpIsValid() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();
            ValidateRequest validateRequest = ValidateRequest.builder().email(user.email()).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);


            mockMvc.perform(post("/verification/validate").param("otp", anyString())
                            .content(objectMapper.writeValueAsString(validateRequest))
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            ArgumentCaptor<UpdateUserRequest> updateUserRequestArgumentCaptor = ArgumentCaptor.forClass(UpdateUserRequest.class);
            verify(userQueryPort).getByEmail(user.email());
            verify(emailOtpService).verifyOtpAndConsume(anyString(), anyString(), any(EmailVerificationOtpNamespace.class));
            verify(userCommandPort).update(eq(user.id()), updateUserRequestArgumentCaptor.capture());

            UpdateUserRequest updateUserRequest = updateUserRequestArgumentCaptor.getValue();
            assertThat(updateUserRequest).isNotNull();
            assertThat(updateUserRequest.emailVerified()).isTrue();
        }

        @Test
        void validate_shouldReturnGone_whenOtpDoesNotMatchEmail() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();
            ValidateRequest validateRequest = ValidateRequest.builder().email(user.email()).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            doThrow(new InvalidOtpException("Invalid otp."))
                    .when(emailOtpService)
                    .verifyOtpAndConsume(anyString(), eq(validateRequest.email()), any(EmailVerificationOtpNamespace.class));

            String responseContent = mockMvc.perform(post("/verification/validate").param("otp", anyString())
                            .content(objectMapper.writeValueAsString(validateRequest))
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isGone())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Invalid otp.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.GONE.value());

            verify(userQueryPort).getByEmail(user.email());
            verify(emailOtpService).verifyOtpAndConsume(anyString(), anyString(), any(EmailVerificationOtpNamespace.class));
            verify(userCommandPort, never()).update(eq(user.id()), any(UpdateUserRequest.class));
        }

        @Test
        void validate_shouldReturnGone_whenOtpExpired() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();
            ValidateRequest validateRequest = ValidateRequest.builder().email(user.email()).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            doThrow(new OtpExpiredException("Otp session expired."))
                    .when(emailOtpService)
                    .verifyOtpAndConsume(anyString(), eq(validateRequest.email()), any(EmailVerificationOtpNamespace.class));

            String responseContent = mockMvc.perform(post("/verification/validate").param("otp",anyString())
                            .content(objectMapper.writeValueAsString(validateRequest))
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isGone())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Otp session expired.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.GONE.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/validate");

            verify(userQueryPort).getByEmail(user.email());
            verify(emailOtpService).verifyOtpAndConsume(anyString(), anyString(), any(EmailVerificationOtpNamespace.class));
            verify(userCommandPort, never()).update(eq(user.id()), any(UpdateUserRequest.class));
        }
    }

}