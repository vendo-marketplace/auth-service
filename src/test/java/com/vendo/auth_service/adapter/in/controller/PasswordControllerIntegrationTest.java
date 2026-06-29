package com.vendo.auth_service.adapter.in.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.auth_service.adapter.otp.out.props.OtpNamespace;
import com.vendo.auth_service.adapter.otp.out.props.PasswordRecoveryOtpNamespace;
import com.vendo.auth_service.adapter.password.in.dto.ResetPasswordRequest;
import com.vendo.auth_service.application.auth.AuthService;
import com.vendo.auth_service.application.auth.command.OtpCommand;
import com.vendo.auth_service.application.auth.dto.UpdateUserRequest;
import com.vendo.auth_service.application.otp.OtpSender;
import com.vendo.auth_service.application.otp.OtpService;
import com.vendo.auth_service.application.otp.common.exception.InvalidOtpException;
import com.vendo.auth_service.application.otp.common.exception.OtpAlreadySentException;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.security.PasswordHashingPort;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserLookupPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.event_lib.otp.OtpEventType;
import com.vendo.redis_lib.exception.OtpExpiredException;
import com.vendo.security_lib.exception.response.ExceptionResponse;
import com.vendo.user_lib.exception.UserNotFoundException;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
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
    private PasswordHashingPort passwordHashingPort;
    @MockitoBean
    private AuthService authService;
    @MockitoBean
    private UserQueryPort userQueryPort;
    @MockitoBean
    private UserCommandPort userCommandPort;
    @MockitoBean
    private OtpSender otpSender;
    @MockitoBean
    private OtpService otpService;
    @MockitoBean
    private UserLookupPort userLookupPort;

    @Nested
    class ForgotPasswordTests {

        @Test
        void forgotPassword_shouldSendForgotPasswordEventSuccessfully() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            mockMvc.perform(post("/password/forgot").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            ArgumentCaptor<OtpCommand> commandArgumentCaptor = ArgumentCaptor.forClass(OtpCommand.class);
            verify(userLookupPort).requireExistence(user.email());
            verify(otpSender).sendOtp(commandArgumentCaptor.capture(), any(PasswordRecoveryOtpNamespace.class));

            OtpCommand command = commandArgumentCaptor.getValue();
            assertThat(command).isNotNull();
            assertThat(command.type()).isEqualTo(OtpEventType.PASSWORD_RECOVERY);
            assertThat(command.email()).isEqualTo(user.email());

        }

        @Test
        void forgotPassword_shouldReturnConflict_whenForgotPasswordEventHasAlreadySent() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            doThrow(new OtpAlreadySentException("Otp already sent."))
                    .when(otpSender)
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
            verify(userLookupPort).requireExistence(user.email());
            verify(otpSender).sendOtp(commandArgumentCaptor.capture(), any(OtpNamespace.class));

            OtpCommand command = commandArgumentCaptor.getValue();
            assertThat(command).isNotNull();
            assertThat(command.email()).isEqualTo(user.email());
            assertThat(command.type()).isEqualTo(OtpEventType.PASSWORD_RECOVERY);

        }

        @Test
        void forgotPassword_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            doThrow(new UserNotFoundException("User not found.")).when(userLookupPort).requireExistence(user.email());

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

            verify(userLookupPort).requireExistence(user.email());
            verify(otpSender, never()).sendOtp(any(OtpCommand.class), any(OtpNamespace.class));
        }
    }

    @Nested
    class ResetPasswordTests {
        @Test
        void resetPassword_shouldResetPassword() throws Exception {
            String otp = "123456";
            String newPassword = "newTestPassword1234@";
            String hashedPassword = "hashedPassword123";
            User user = UserDataBuilder.withAllFields()
                    .password(newPassword)
                    .build();
            ResetPasswordRequest resetPasswordRequest = ResetPasswordRequest.builder()
                    .password(newPassword).build();

            when(otpService.peek(eq(otp), any(PasswordRecoveryOtpNamespace.class))).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            when(passwordHashingPort.matches(newPassword, user.password())).thenReturn(false);
            when(passwordHashingPort.hash(newPassword)).thenReturn(hashedPassword);

            mockMvc.perform(put("/password/reset").param("otp", otp)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(resetPasswordRequest)))
                    .andExpect(status().isOk());

            ArgumentCaptor<UpdateUserRequest> usertArgumentCaptor = ArgumentCaptor.forClass(UpdateUserRequest.class);
            verify(otpService).peek(eq(otp), any(PasswordRecoveryOtpNamespace.class));
            verify(userQueryPort).getByEmail(user.email());
            verify(passwordHashingPort).matches(newPassword, user.password());
            verify(passwordHashingPort).hash(newPassword);
            verify(userCommandPort).update(eq(user.id()), usertArgumentCaptor.capture());

            UpdateUserRequest updateUserRequestCaptured = usertArgumentCaptor.getValue();
            assertThat(updateUserRequestCaptured).isNotNull();
            assertThat(updateUserRequestCaptured.password()).isEqualTo(hashedPassword);
            assertThat(updateUserRequestCaptured.birthDate()).isNull();
            assertThat(updateUserRequestCaptured.fullName()).isNull();
        }

        @Test
        void resetPassword_shouldReturnGone_whenOtpExpired() throws Exception {
            String otp = "123456";
            String newPassword = "newTestPassword1234@";
            ResetPasswordRequest resetPasswordRequest = ResetPasswordRequest.builder().password(newPassword).build();

            doThrow(new OtpExpiredException("Otp session expired."))
                    .when(otpService)
                    .peek(eq(otp), any(PasswordRecoveryOtpNamespace.class));

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

            verify(otpService).peek(eq(otp), any(PasswordRecoveryOtpNamespace.class));
            verifyNoInteractions(userQueryPort, passwordHashingPort, userCommandPort);
        }

        @Test
        void resetPassword_shouldReturnGone_whenInvalidOtp() throws Exception {
            String otp = "123456";
            String newPassword = "newTestPassword1234@";
            ResetPasswordRequest resetPasswordRequest = ResetPasswordRequest.builder().password(newPassword).build();

            doThrow(new InvalidOtpException("Invalid otp."))
                    .when(otpService)
                    .peek(eq(otp), any(PasswordRecoveryOtpNamespace.class));

            String responseContent = mockMvc.perform(put("/password/reset").param("otp", otp)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(resetPasswordRequest)))
                    .andExpect(status().isGone())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotBlank();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Invalid otp.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.GONE.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/reset");

            verify(otpService).peek(eq(otp), any(PasswordRecoveryOtpNamespace.class));
            verifyNoInteractions(userQueryPort, passwordHashingPort, userCommandPort);
        }

        @Test
        void resetPassword_shouldReturnNotFound_whenUserNotFound() throws Exception {
            String otp = "123456";
            String newPassword = "newTestPassword1234@";
            User user = UserDataBuilder.withAllFields().build();
            ResetPasswordRequest resetPasswordRequest = ResetPasswordRequest.builder().password(newPassword).build();

            when(otpService.peek(eq(otp), any(PasswordRecoveryOtpNamespace.class))).thenReturn(user.email());
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

            verify(otpService).peek(eq(otp), any(PasswordRecoveryOtpNamespace.class));
            verify(userQueryPort).getByEmail(user.email());
            verifyNoInteractions(passwordHashingPort, userCommandPort);
        }

        @Test
        void resetPassword_shouldReturnConflict_whenPasswordIsSame() throws Exception {
            String otp = "123456";
            String newPassword = "newTestPassword1234@";
            User user = UserDataBuilder.withAllFields().build();
            ResetPasswordRequest resetPasswordRequest = ResetPasswordRequest.builder().password(newPassword).build();

            when(otpService.peek(eq(otp), any(PasswordRecoveryOtpNamespace.class))).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            when(passwordHashingPort.matches(newPassword, user.password())).thenReturn(true);

            String responseContent = mockMvc.perform(put("/password/reset").param("otp", otp)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(resetPasswordRequest)))
                    .andExpect(status().isConflict())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotBlank();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("The new password cannot be the same as the current password.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/reset");

            verify(otpService).peek(eq(otp), any(PasswordRecoveryOtpNamespace.class));
            verify(userQueryPort).getByEmail(user.email());
            verify(passwordHashingPort).matches(newPassword, user.password());
            verify(userCommandPort, never()).update(anyString(), any(UpdateUserRequest.class));
        }
    }

    @Nested
    class ResendOtpTests {

        @Test
        void resendOtp_shouldSuccessfullyResendOtp() throws Exception {
            ArgumentCaptor<OtpCommand> commandArgumentCaptor = ArgumentCaptor.forClass(OtpCommand.class);
            User user = UserDataBuilder.withAllFields().build();

            doNothing().when(otpSender).resendOtp(commandArgumentCaptor.capture(), any(PasswordRecoveryOtpNamespace.class));

            mockMvc.perform(put("/password/resend-otp").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            OtpCommand command = commandArgumentCaptor.getValue();

            assertThat(command).isNotNull();
            assertThat(command.type()).isEqualTo(OtpEventType.PASSWORD_RECOVERY);
            assertThat(command.email()).isEqualTo(user.email());

            verify(userLookupPort).requireExistence(user.email());
            verify(otpSender).resendOtp(eq(command), any(PasswordRecoveryOtpNamespace.class));
        }

        @Test
        void resendOtp_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            doThrow(new UserNotFoundException("User not found.")).when(userLookupPort).requireExistence(user.email());

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

            verify(userLookupPort).requireExistence(user.email());
            verify(otpSender, never()).resendOtp(any(OtpCommand.class), any(PasswordRecoveryOtpNamespace.class));
        }

        @Test
        void resendOtp_shouldReturnGone_whenOtpSessionExpired() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            doThrow(new OtpExpiredException("Otp session expired.")).when(otpSender).resendOtp(any(OtpCommand.class), any(PasswordRecoveryOtpNamespace.class));

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

            verify(userLookupPort).requireExistence(user.email());
            verify(otpSender).resendOtp(any(OtpCommand.class), any(PasswordRecoveryOtpNamespace.class));
        }

        @Test
        void resendOtp_shouldReturnConflict_whenOtpAlreadySent() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            doThrow(new OtpAlreadySentException("Otp already sent."))
                    .when(otpSender)
                    .resendOtp(any(OtpCommand.class), any(PasswordRecoveryOtpNamespace.class));

            String responseContent = mockMvc.perform(put("/password/resend-otp").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isConflict())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotBlank();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Otp already sent.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/resend-otp");

            verify(userLookupPort).requireExistence(user.email());
            verify(otpSender).resendOtp(any(OtpCommand.class), any(PasswordRecoveryOtpNamespace.class));
        }
    }

}
