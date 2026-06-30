package com.vendo.auth_service.adapter.in.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.auth_service.adapter.otp.out.props.EmailVerificationOtpNamespace;
import com.vendo.auth_service.application.auth.command.OtpCommand;
import com.vendo.auth_service.application.auth.dto.UpdateUserRequest;
import com.vendo.auth_service.application.otp.OtpSender;
import com.vendo.auth_service.application.otp.OtpService;
import com.vendo.auth_service.domain.otp.exception.OtpAlreadySentException;
import com.vendo.auth_service.domain.otp.exception.TooManyOtpRequestsException;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class VerificationControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;
    @MockitoBean
    private UserQueryPort userQueryPort;
    @MockitoBean
    private UserCommandPort userCommandPort;
    @MockitoBean
    private UserLookupPort userLookupPort;
    @MockitoBean
    private OtpService otpService;
    @MockitoBean
    private OtpSender otpSender;

    @Nested
    class SendOtpTests {

        @Test
        void sendOtp_shouldSendEmailVerificationEventSuccessfully() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(false).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            mockMvc.perform(MockMvcRequestBuilders.post("/verification/send-otp").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            ArgumentCaptor<OtpCommand> commandArgumentCaptor = ArgumentCaptor.forClass(OtpCommand.class);
            verify(userQueryPort).getByEmail(user.email());
            verify(otpSender).sendOtp(commandArgumentCaptor.capture(), any(EmailVerificationOtpNamespace.class));

            OtpCommand command = commandArgumentCaptor.getValue();
            assertThat(command).isNotNull();
            assertThat(command.email()).isEqualTo(user.email());
            assertThat(command.type()).isEqualTo(OtpEventType.EMAIL_VERIFICATION);
        }

        @Test
        void sendOtp_shouldReturnConflict_whenUserAlreadyVerified() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(true).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            String responseContent = mockMvc.perform(post("/verification/send-otp")
                            .contentType(MediaType.APPLICATION_JSON).param("email", user.email()))
                    .andExpect(status().isConflict())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("User email is already verified.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/send-otp");

            verify(userQueryPort).getByEmail(user.email());
            verify(otpSender, never()).sendOtp(any(OtpCommand.class), any(EmailVerificationOtpNamespace.class));
        }

        @Test
        void sendOtp_shouldReturnConflict_whenEmailVerificationEventHasAlreadySent() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(false).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            ArgumentCaptor<OtpCommand> commandArgumentCaptor = ArgumentCaptor.forClass(OtpCommand.class);
            doThrow(new OtpAlreadySentException("Otp already sent."))
                    .when(otpSender)
                    .sendOtp(commandArgumentCaptor.capture(), any(EmailVerificationOtpNamespace.class));

            String responseContent = mockMvc.perform(post("/verification/send-otp")
                            .contentType(MediaType.APPLICATION_JSON).param("email", user.email()))
                    .andExpect(status().isConflict())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Otp already sent.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/send-otp");

            OtpCommand command = commandArgumentCaptor.getValue();
            assertThat(command).isNotNull();
            assertThat(command.email()).isEqualTo(user.email());
            assertThat(command.type()).isEqualTo(OtpEventType.EMAIL_VERIFICATION);

            verify(userQueryPort).getByEmail(user.email());
            verify(otpSender).sendOtp(eq(command), any(EmailVerificationOtpNamespace.class));
        }

        @Test
        void sendOtp_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            doThrow(new UserNotFoundException("User not found.")).when(userQueryPort).getByEmail(user.email());

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
            verify(otpSender, never()).sendOtp(any(OtpCommand.class), any(EmailVerificationOtpNamespace.class));
        }
    }

    @Nested
    class ResendOtpTests {

        @Test
        void resendOtp_shouldSuccessfullyResendOtp() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(false).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            mockMvc.perform(post("/verification/resend-otp").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            verify(userQueryPort).getByEmail(user.email());
            verify(otpSender).resendOtp(any(OtpCommand.class), any(EmailVerificationOtpNamespace.class));
        }

        @Test
        void resendOtp_shouldReturnConflict_whenUserAlreadyVerified() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(true).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            String responseContent = mockMvc.perform(post("/verification/resend-otp").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isConflict())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("User email is already verified.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/resend-otp");

            verify(userQueryPort).getByEmail(user.email());
            verify(otpSender, never()).resendOtp(any(OtpCommand.class), any(EmailVerificationOtpNamespace.class));
        }

        @Test
        void resendOtp_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            doThrow(new UserNotFoundException("User not found.")).when(userQueryPort).getByEmail(user.email());

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
            verify(otpSender, never()).resendOtp(any(OtpCommand.class), any(EmailVerificationOtpNamespace.class));
        }

        @Test
        void resendOtp_shouldReturnTooManyRequests_whenTooManyAttempts() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(false).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            doThrow(new TooManyOtpRequestsException("Reached maximum attempts."))
                    .when(otpSender)
                    .resendOtp(any(OtpCommand.class), any(EmailVerificationOtpNamespace.class));

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
            verify(otpSender).resendOtp(any(OtpCommand.class), any(EmailVerificationOtpNamespace.class));
        }

        @Test
        void resendOtp_shouldReturnGone_whenOtpSessionExpired() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(false).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            doThrow(new OtpExpiredException("Otp session expired."))
                    .when(otpSender)
                    .resendOtp(any(OtpCommand.class), any(EmailVerificationOtpNamespace.class));


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

            verify(userQueryPort).getByEmail(user.email());
            verify(otpSender).resendOtp(any(OtpCommand.class), any(EmailVerificationOtpNamespace.class));
        }
    }

    @Nested
    class ValidateTests {

        @Test
        void validate_shouldVerifyUser_whenOtpIsValid() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(false).build();
            String otp = "123456";

            when(otpService.consume(eq(otp), any(EmailVerificationOtpNamespace.class))).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            mockMvc.perform(post("/verification/validate").param("otp", otp)
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            ArgumentCaptor<UpdateUserRequest> updateUserArgumentCaptor = ArgumentCaptor.forClass(UpdateUserRequest.class);
            verify(otpService).consume(eq(otp), any(EmailVerificationOtpNamespace.class));
            verify(userQueryPort).getByEmail(user.email());
            verify(userCommandPort).update(eq(user.id()), updateUserArgumentCaptor.capture());

            UpdateUserRequest updateUserArgumentCaptorValue = updateUserArgumentCaptor.getValue();
            assertThat(updateUserArgumentCaptorValue).isNotNull();
            assertThat(updateUserArgumentCaptorValue.emailVerified()).isTrue();
        }

        @Test
        void validate_shouldReturnConflict_whenUserAlreadyVerified() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(true).build();
            String otp = "123456";

            when(otpService.consume(eq(otp), any(EmailVerificationOtpNamespace.class))).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            String responseContent = mockMvc.perform(post("/verification/validate").param("otp", otp)
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isConflict())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("User email is already verified.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/validate");

            verify(otpService).consume(eq(otp), any(EmailVerificationOtpNamespace.class));
            verify(userQueryPort).getByEmail(user.email());
            verify(userCommandPort, never()).update(eq(user.id()), any(UpdateUserRequest.class));
        }

        @Test
        void validate_shouldReturnGone_whenOtpExpired() throws Exception {
            User user = UserDataBuilder.withAllFields().build();
            String otp = "123456";

            doThrow(new OtpExpiredException("Otp session expired.")).when(otpService).consume(anyString(), any(EmailVerificationOtpNamespace.class));

            String responseContent = mockMvc.perform(post("/verification/validate").param("otp", otp)
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

            verify(otpService).consume(anyString(), any(EmailVerificationOtpNamespace.class));
            verify(userQueryPort, never()).getByEmail(user.email());
            verify(userCommandPort, never()).update(eq(user.id()), any(UpdateUserRequest.class));
        }
    }

}
