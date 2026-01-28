package com.vendo.auth_service.adapter.in.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.auth_service.application.AuthService;
import com.vendo.auth_service.application.otp.EmailOtpService;
import com.vendo.auth_service.application.otp.common.exception.OtpAlreadySentException;
import com.vendo.auth_service.domain.user.common.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.auth_service.domain.user.common.exception.UserNotFoundException;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.auth_service.system.redis.common.dto.ResetPasswordRequest;
import com.vendo.auth_service.system.redis.common.namespace.otp.OtpNamespace;
import com.vendo.auth_service.system.redis.common.namespace.otp.PasswordRecoveryOtpNamespace;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class PasswordControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private UserQueryPort userQueryPort;

    @MockitoBean
    private UserCommandPort userCommandPort;

    @MockitoBean
    private EmailOtpService emailOtpService;

    @Nested
    class ForgotPasswordTests {

        @Test
        void forgotPassword_shouldSendForgotPasswordEventSuccessfully() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            mockMvc.perform(post("/password/forgot").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            ArgumentCaptor<EmailOtpEvent> emailOtpEventArgumentCaptor = ArgumentCaptor.forClass(EmailOtpEvent.class);
            verify(userQueryPort).getByEmail(user.email());
            verify(emailOtpService).sendOtp(emailOtpEventArgumentCaptor.capture(), any(PasswordRecoveryOtpNamespace.class));

            EmailOtpEvent emailOtpEvent = emailOtpEventArgumentCaptor.getValue();
            assertThat(emailOtpEvent).isNotNull();
            assertThat(emailOtpEvent.getOtpEventType()).isEqualTo(EmailOtpEvent.OtpEventType.PASSWORD_RECOVERY);
            assertThat(emailOtpEvent.getEmail()).isEqualTo(user.email());
            assertThat(emailOtpEvent.getOtp()).isBlank();
        }

        @Test
        void forgotPassword_shouldReturnConflict_whenForgotPasswordEventHasAlreadySent() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            doThrow(new OtpAlreadySentException("Otp has already sent."))
                    .when(emailOtpService)
                    .sendOtp(any(EmailOtpEvent.class), any(PasswordRecoveryOtpNamespace.class));

            String responseContent = mockMvc.perform(post("/password/forgot")
                            .contentType(MediaType.APPLICATION_JSON).param("email", user.email()))
                    .andExpect(status().isConflict())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotBlank();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Otp has already sent.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/forgot");

            ArgumentCaptor<EmailOtpEvent> emailOtpEventArgumentCaptor = ArgumentCaptor.forClass(EmailOtpEvent.class);
            verify(userQueryPort).getByEmail(user.email());
            verify(emailOtpService).sendOtp(emailOtpEventArgumentCaptor.capture(), any(OtpNamespace.class));

            EmailOtpEvent emailOtpEvent = emailOtpEventArgumentCaptor.getValue();
            assertThat(emailOtpEvent).isNotNull();
            assertThat(emailOtpEvent.getEmail()).isEqualTo(user.email());
            assertThat(emailOtpEvent.getOtpEventType()).isEqualTo(EmailOtpEvent.OtpEventType.PASSWORD_RECOVERY);
            assertThat(emailOtpEvent.getOtp()).isBlank();
        }

        @Test
        void forgotPassword_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();

            doThrow(new UserNotFoundException("User not found.")).when(userQueryPort).getByEmail(user.email());

            String responseContent = mockMvc.perform(post("/password/forgot")
                            .contentType(MediaType.APPLICATION_JSON).param("email", user.email()))
                    .andExpect(status().isNotFound())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotBlank();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("User not found.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/forgot");

            verify(userQueryPort).getByEmail(user.email());
            verify(emailOtpService, never()).sendOtp(any(EmailOtpEvent.class), any(OtpNamespace.class));
        }
    }

    @Nested
    class ResetPasswordTests {
        @Test
        void resetPassword_shouldResetPassword() throws Exception {
            String otp = "123456";
            String newPassword = "newTestPassword1234@";
            User user = UserDataBuilder.buildUserAllFields().build();
            UpdateUserRequest updateUserRequest = UpdateUserRequest.builder().password(newPassword).build();
            ResetPasswordRequest resetPasswordRequest = ResetPasswordRequest.builder()
                    .password(newPassword).build();

            when(emailOtpService.verifyOtpAndConsume(eq(otp), isNull(), any(PasswordRecoveryOtpNamespace.class))).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            doNothing().when(userCommandPort).update(user.id(), updateUserRequest);

            mockMvc.perform(put("/password/reset").param("otp", otp)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(resetPasswordRequest)))
                    .andExpect(status().isOk());

            ArgumentCaptor<UpdateUserRequest> userRequestArgumentCaptor = ArgumentCaptor.forClass(UpdateUserRequest.class);
            verify(emailOtpService).verifyOtpAndConsume(eq(otp), isNull(), any(PasswordRecoveryOtpNamespace.class));
            verify(userQueryPort).getByEmail(user.email());
            verify(userCommandPort).update(eq(user.id()), userRequestArgumentCaptor.capture());

            UpdateUserRequest updateUserRequestCaptured = userRequestArgumentCaptor.getValue();
            assertThat(updateUserRequestCaptured).isNotNull();
            assertThat(updateUserRequestCaptured.password()).isNotBlank();
            assertThat(updateUserRequestCaptured.birthDate()).isNull();
            assertThat(updateUserRequestCaptured.fullName()).isNull();
        }

        @Test
        void resetPassword_shouldReturnGone_whenTokenExpired() throws Exception {
            String otp = "123456";
            String newPassword = "newTestPassword1234@";
            String email = "test@gmail.com";
            ResetPasswordRequest resetPasswordRequest = ResetPasswordRequest.builder().password(newPassword).build();

            doThrow(new OtpExpiredException("Otp session expired."))
                    .when(emailOtpService)
                    .verifyOtpAndConsume(eq(otp), isNull(), any(PasswordRecoveryOtpNamespace.class));

            String responseContent = mockMvc.perform(put("/password/reset").param("otp", otp)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(resetPasswordRequest)))
                    .andExpect(status().isGone())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotBlank();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Otp session expired.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.GONE.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/reset");

            verify(emailOtpService).verifyOtpAndConsume(eq(otp), isNull(), any(PasswordRecoveryOtpNamespace.class));
            verify(userQueryPort, never()).getByEmail(email);
            verify(userCommandPort, never()).update(anyString(), any(UpdateUserRequest.class));
        }

        @Test
        void resetPassword_shouldReturnNotFound_whenUserNotFound() throws Exception {
            String otp = "123456";
            String newPassword = "newTestPassword1234@";
            User user = UserDataBuilder.buildUserAllFields().build();
            ResetPasswordRequest resetPasswordRequest = ResetPasswordRequest.builder().password(newPassword).build();

            when(emailOtpService.verifyOtpAndConsume(eq(otp), isNull(), any(PasswordRecoveryOtpNamespace.class))).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenThrow(new UserNotFoundException("User not found."));

            String responseContent = mockMvc.perform(put("/password/reset").param("otp", otp)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(resetPasswordRequest)))
                    .andExpect(status().isNotFound())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotBlank();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("User not found.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/reset");

            verify(emailOtpService).verifyOtpAndConsume(eq(otp), isNull(), any(PasswordRecoveryOtpNamespace.class));
            verify(userQueryPort).getByEmail(user.email());
            verify(userCommandPort, never()).update(anyString(), any(UpdateUserRequest.class));
        }
    }

    @Nested
    class ResendOtpTests {

        @Test
        void resendOtp_shouldSuccessfullyResendOtp() throws Exception {
            ArgumentCaptor<EmailOtpEvent> emailOtpEventArgumentCaptor = ArgumentCaptor.forClass(EmailOtpEvent.class);
            User user = UserDataBuilder.buildUserAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            doNothing().when(emailOtpService).resendOtp(emailOtpEventArgumentCaptor.capture(), any(PasswordRecoveryOtpNamespace.class));

            mockMvc.perform(put("/password/resend-otp").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            EmailOtpEvent emailOtpEvent = emailOtpEventArgumentCaptor.getValue();
            verify(userQueryPort).getByEmail(user.email());
            verify(emailOtpService).resendOtp(eq(emailOtpEvent), any(PasswordRecoveryOtpNamespace.class));

            assertThat(emailOtpEvent).isNotNull();
            assertThat(emailOtpEvent.getOtpEventType()).isEqualTo(EmailOtpEvent.OtpEventType.PASSWORD_RECOVERY);
            assertThat(emailOtpEvent.getEmail()).isEqualTo(user.email());
            assertThat(emailOtpEvent.getOtp()).isBlank();
        }

        @Test
        void resendOtp_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenThrow(new UserNotFoundException("User not found."));

            String responseContent = mockMvc.perform(put("/password/resend-otp").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isNotFound())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("User not found.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/resend-otp");

            verify(userQueryPort).getByEmail(user.email());
            verify(emailOtpService, never()).resendOtp(any(EmailOtpEvent.class), any(PasswordRecoveryOtpNamespace.class));
        }

        @Test
        void resendOtp_shouldReturnGone_whenOtpSessionExpired() throws Exception {
            User user = UserDataBuilder.buildUserAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            doThrow(new OtpExpiredException("Otp session expired.")).when(emailOtpService).resendOtp(any(EmailOtpEvent.class), any(PasswordRecoveryOtpNamespace.class));

            String responseContent = mockMvc.perform(put("/password/resend-otp").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isGone())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Otp session expired.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.GONE.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/resend-otp");

            verify(userQueryPort).getByEmail(user.email());
            verify(emailOtpService).resendOtp(any(EmailOtpEvent.class), any(PasswordRecoveryOtpNamespace.class));
        }
    }
}
