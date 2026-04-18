package com.vendo.auth_service.adapter.in.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.auth_service.adapter.otp.out.props.OtpNamespace;
import com.vendo.auth_service.adapter.otp.out.props.PasswordRecoveryOtpNamespace;
import com.vendo.auth_service.adapter.password.in.dto.ResetPasswordRequest;
import com.vendo.auth_service.application.auth.AuthService;
import com.vendo.auth_service.application.auth.command.OtpCommand;
import com.vendo.auth_service.application.auth.dto.UpdateUserRequest;
import com.vendo.auth_service.application.otp.OtpService;
import com.vendo.auth_service.application.otp.OtpVerifier;
import com.vendo.auth_service.application.otp.common.exception.OtpAlreadySentException;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.core_lib.exception.ExceptionResponse;
import com.vendo.event_lib.OtpEventType;
import com.vendo.redis_lib.exception.OtpExpiredException;
import com.vendo.user_lib.exception.UserNotFoundException;
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
class PasswordControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private PasswordRecoveryOtpNamespace passwordRecoveryOtpNamespace;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private UserQueryPort userQueryPort;

    @MockitoBean
    private UserCommandPort userCommandPort;

    @MockitoBean
    private OtpService otpService;

    @MockitoBean
    private OtpVerifier otpVerifier;

    @Nested
    class ForgotPasswordTests {

        @Test
        void forgotPassword_shouldSendForgotPasswordEventSuccessfully() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            mockMvc.perform(post("/password/forgot").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            ArgumentCaptor<OtpCommand> commandArgumentCaptor = ArgumentCaptor.forClass(OtpCommand.class);
            verify(userQueryPort).getByEmail(user.email());
            verify(otpService).sendOtp(commandArgumentCaptor.capture(), any(PasswordRecoveryOtpNamespace.class));

            OtpCommand command = commandArgumentCaptor.getValue();
            assertThat(command).isNotNull();
            assertThat(command.type()).isEqualTo(OtpEventType.PASSWORD_RECOVERY);
            assertThat(command.email()).isEqualTo(user.email());
        }

        @Test
        void forgotPassword_shouldReturnConflict_whenForgotPasswordEventHasAlreadySent() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            doThrow(new OtpAlreadySentException("Otp already sent."))
                    .when(otpService)
                    .sendOtp(any(OtpCommand.class), any(PasswordRecoveryOtpNamespace.class));

            String responseContent = mockMvc.perform(post("/password/forgot")
                            .contentType(MediaType.APPLICATION_JSON).param("email", user.email()))
                    .andExpect(status().isConflict())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotBlank();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Otp already sent.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/forgot");

            ArgumentCaptor<OtpCommand> commandArgumentCaptor = ArgumentCaptor.forClass(OtpCommand.class);
            verify(userQueryPort).getByEmail(user.email());
            verify(otpService).sendOtp(commandArgumentCaptor.capture(), any(OtpNamespace.class));

            OtpCommand command = commandArgumentCaptor.getValue();
            assertThat(command).isNotNull();
            assertThat(command.email()).isEqualTo(user.email());
            assertThat(command.type()).isEqualTo(OtpEventType.PASSWORD_RECOVERY);
        }

        @Test
        void forgotPassword_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

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
            verify(otpService, never()).sendOtp(any(OtpCommand.class), any(OtpNamespace.class));
        }
    }

    @Nested
    class ResetPasswordTests {
        @Test
        void resetPassword_shouldResetPassword() throws Exception {
            String otp = "123456";
            String newPassword = "newTestPassword1234@";
            User user = UserDataBuilder.withAllFields()
                    .password(newPassword)
                    .build();
            ResetPasswordRequest resetPasswordRequest = ResetPasswordRequest.builder()
                    .password(newPassword).build();

            when(otpVerifier.verify(eq(otp), any(PasswordRecoveryOtpNamespace.class))).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            doNothing().when(userCommandPort).update(user.id(), UpdateUserRequest.builder().password(newPassword).build());

            mockMvc.perform(put("/password/reset").param("otp", otp)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(resetPasswordRequest)))
                    .andExpect(status().isOk());

            ArgumentCaptor<UpdateUserRequest> usertArgumentCaptor = ArgumentCaptor.forClass(UpdateUserRequest.class);
            verify(otpVerifier).verify(eq(otp), any(PasswordRecoveryOtpNamespace.class));
            verify(userQueryPort).getByEmail(user.email());
            verify(userCommandPort).update(eq(user.id()), usertArgumentCaptor.capture());

            UpdateUserRequest updateUserRequestCaptured = usertArgumentCaptor.getValue();
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
                    .when(otpVerifier)
                    .verify(eq(otp), any(PasswordRecoveryOtpNamespace.class));

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

            verify(otpVerifier).verify(eq(otp), any(PasswordRecoveryOtpNamespace.class));
            verify(userQueryPort, never()).getByEmail(email);
            verify(userCommandPort, never()).update(anyString(), any(UpdateUserRequest.class));
        }

        @Test
        void resetPassword_shouldReturnNotFound_whenUserNotFound() throws Exception {
            String otp = "123456";
            String newPassword = "newTestPassword1234@";
            User user = UserDataBuilder.withAllFields().build();
            ResetPasswordRequest resetPasswordRequest = ResetPasswordRequest.builder().password(newPassword).build();

            when(otpVerifier.verify(eq(otp), any(PasswordRecoveryOtpNamespace.class))).thenReturn(user.email());
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

            verify(otpVerifier).verify(eq(otp), any(PasswordRecoveryOtpNamespace.class));
            verify(userQueryPort).getByEmail(user.email());
            verify(userCommandPort, never()).update(anyString(), any(UpdateUserRequest.class));
        }
    }

    @Nested
    class ResendOtpTests {

        @Test
        void resendOtp_shouldSuccessfullyResendOtp() throws Exception {
            ArgumentCaptor<OtpCommand> commandArgumentCaptor = ArgumentCaptor.forClass(OtpCommand.class);
            User user = UserDataBuilder.withAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            doNothing().when(otpService).resendOtp(commandArgumentCaptor.capture(), any(PasswordRecoveryOtpNamespace.class));

            mockMvc.perform(put("/password/resend-otp").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            OtpCommand command = commandArgumentCaptor.getValue();
            verify(userQueryPort).getByEmail(user.email());
            verify(otpService).resendOtp(eq(command), any(PasswordRecoveryOtpNamespace.class));

            assertThat(command).isNotNull();
            assertThat(command.type()).isEqualTo(OtpEventType.PASSWORD_RECOVERY);
            assertThat(command.email()).isEqualTo(user.email());
        }

        @Test
        void resendOtp_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

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
            verify(otpService, never()).resendOtp(any(OtpCommand.class), any(PasswordRecoveryOtpNamespace.class));
        }

        @Test
        void resendOtp_shouldReturnGone_whenOtpSessionExpired() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            doThrow(new OtpExpiredException("Otp session expired.")).when(otpService).resendOtp(any(OtpCommand.class), any(PasswordRecoveryOtpNamespace.class));

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
            verify(otpService).resendOtp(any(OtpCommand.class), any(PasswordRecoveryOtpNamespace.class));
        }
    }

}
