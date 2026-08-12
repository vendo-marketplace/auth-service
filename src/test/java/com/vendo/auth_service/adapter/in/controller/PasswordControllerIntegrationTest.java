package com.vendo.auth_service.adapter.in.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.auth_service.adapter.code.out.props.CodeNamespace;
import com.vendo.auth_service.adapter.code.out.props.PasswordRecoveryCodeNamespace;
import com.vendo.auth_service.adapter.password.in.dto.ResetPasswordRequest;
import com.vendo.auth_service.application.auth.command.CodeCommand;
import com.vendo.auth_service.application.auth.dto.UpdateUserRequest;
import com.vendo.auth_service.application.code.CodeSender;
import com.vendo.auth_service.application.code.CodeService;
import com.vendo.auth_service.domain.code.exception.InvalidCodeException;
import com.vendo.auth_service.domain.code.exception.CodeAlreadySentException;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.auth.usecase.AuthUseCase;
import com.vendo.auth_service.port.security.PasswordHashingPort;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserLookupPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.event_lib.code.CodeEventType;
import com.vendo.redis_lib.exception.CodeExpiredException;
import com.vendo.security_lib.exception.ExceptionResponse;
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
    private PasswordRecoveryCodeNamespace passwordRecoveryCodeNamespace;
    @MockitoBean
    private PasswordHashingPort passwordHashingPort;
    @MockitoBean
    private AuthUseCase authUseCase;
    @MockitoBean
    private UserQueryPort userQueryPort;
    @MockitoBean
    private UserCommandPort userCommandPort;
    @MockitoBean
    private CodeSender codeSender;
    @MockitoBean
    private CodeService codeService;
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

            ArgumentCaptor<CodeCommand> commandArgumentCaptor = ArgumentCaptor.forClass(CodeCommand.class);
            verify(userLookupPort).requireExistence(user.email());
            verify(codeSender).send(commandArgumentCaptor.capture(), any(PasswordRecoveryCodeNamespace.class));

            CodeCommand command = commandArgumentCaptor.getValue();
            assertThat(command).isNotNull();
            assertThat(command.type()).isEqualTo(CodeEventType.PASSWORD_RECOVERY);
            assertThat(command.email()).isEqualTo(user.email());
        }

        @Test
        void forgotPassword_shouldReturnConflict_whenForgotPasswordEventHasAlreadySent() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            doThrow(new CodeAlreadySentException("Code already sent."))
                    .when(codeSender)
                    .send(any(CodeCommand.class), any(PasswordRecoveryCodeNamespace.class));

            String responseContent = mockMvc.perform(post("/password/forgot")
                            .contentType(MediaType.APPLICATION_JSON).param("email", user.email()))
                    .andExpect(status().isConflict())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotBlank();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Code already sent.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/forgot");

            ArgumentCaptor<CodeCommand> commandArgumentCaptor = ArgumentCaptor.forClass(CodeCommand.class);
            verify(userLookupPort).requireExistence(user.email());
            verify(codeSender).send(commandArgumentCaptor.capture(), any(CodeNamespace.class));

            CodeCommand command = commandArgumentCaptor.getValue();
            assertThat(command).isNotNull();
            assertThat(command.email()).isEqualTo(user.email());
            assertThat(command.type()).isEqualTo(CodeEventType.PASSWORD_RECOVERY);

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
            verify(codeSender, never()).send(any(CodeCommand.class), any(CodeNamespace.class));
        }
    }

    @Nested
    class ResetPasswordTests {
        @Test
        void resetPassword_shouldResetPassword() throws Exception {
            String code = "123456";
            String newPassword = "newTestPassword1234@";
            String hashedPassword = "hashedPassword123";
            User user = UserDataBuilder.withAllFields()
                    .password(newPassword)
                    .build();
            ResetPasswordRequest resetPasswordRequest = ResetPasswordRequest.builder()
                    .password(newPassword).build();

            when(codeService.peek(eq(code), any(PasswordRecoveryCodeNamespace.class))).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            when(passwordHashingPort.matches(newPassword, user.password())).thenReturn(false);
            when(passwordHashingPort.hash(newPassword)).thenReturn(hashedPassword);

            mockMvc.perform(put("/password/reset").param("code", code)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(resetPasswordRequest)))
                    .andExpect(status().isOk());

            ArgumentCaptor<UpdateUserRequest> usertArgumentCaptor = ArgumentCaptor.forClass(UpdateUserRequest.class);
            verify(codeService).peek(eq(code), any(PasswordRecoveryCodeNamespace.class));
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
        void resetPassword_shouldReturnGone_whenCodeExpired() throws Exception {
            String code = "123456";
            String newPassword = "newTestPassword1234@";
            ResetPasswordRequest resetPasswordRequest = ResetPasswordRequest.builder().password(newPassword).build();

            doThrow(new CodeExpiredException("Code session expired."))
                    .when(codeService)
                    .peek(eq(code), any(PasswordRecoveryCodeNamespace.class));

            String responseContent = mockMvc.perform(put("/password/reset").param("code", code)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(resetPasswordRequest)))
                    .andExpect(status().isGone())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotBlank();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Code session expired.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.GONE.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/reset");

            verify(codeService).peek(eq(code), any(PasswordRecoveryCodeNamespace.class));
            verifyNoInteractions(userQueryPort, passwordHashingPort, userCommandPort);
        }

        @Test
        void resetPassword_shouldReturnGone_whenInvalidCode() throws Exception {
            String code = "123456";
            String newPassword = "newTestPassword1234@";
            ResetPasswordRequest resetPasswordRequest = ResetPasswordRequest.builder().password(newPassword).build();

            doThrow(new InvalidCodeException("Invalid code."))
                    .when(codeService)
                    .peek(eq(code), any(PasswordRecoveryCodeNamespace.class));

            String responseContent = mockMvc.perform(put("/password/reset").param("code", code)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(resetPasswordRequest)))
                    .andExpect(status().isGone())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotBlank();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Invalid code.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.GONE.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/reset");

            verify(codeService).peek(eq(code), any(PasswordRecoveryCodeNamespace.class));
            verifyNoInteractions(userQueryPort, passwordHashingPort, userCommandPort);
        }

        @Test
        void resetPassword_shouldReturnNotFound_whenUserNotFound() throws Exception {
            String code = "123456";
            String newPassword = "newTestPassword1234@";
            User user = UserDataBuilder.withAllFields().build();
            ResetPasswordRequest resetPasswordRequest = ResetPasswordRequest.builder().password(newPassword).build();

            when(codeService.peek(eq(code), any(PasswordRecoveryCodeNamespace.class))).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenThrow(new UserNotFoundException("User not found."));

            String responseContent = mockMvc.perform(put("/password/reset").param("code", code)
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

            verify(codeService).peek(eq(code), any(PasswordRecoveryCodeNamespace.class));
            verify(userQueryPort).getByEmail(user.email());
            verifyNoInteractions(passwordHashingPort, userCommandPort);
        }

        @Test
        void resetPassword_shouldReturnConflict_whenPasswordIsSame() throws Exception {
            String code = "123456";
            String newPassword = "newTestPassword1234@";
            User user = UserDataBuilder.withAllFields().build();
            ResetPasswordRequest resetPasswordRequest = ResetPasswordRequest.builder().password(newPassword).build();

            when(codeService.peek(eq(code), any(PasswordRecoveryCodeNamespace.class))).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenReturn(user);
            when(passwordHashingPort.matches(newPassword, user.password())).thenReturn(true);

            String responseContent = mockMvc.perform(put("/password/reset").param("code", code)
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

            verify(codeService).peek(eq(code), any(PasswordRecoveryCodeNamespace.class));
            verify(userQueryPort).getByEmail(user.email());
            verify(passwordHashingPort).matches(newPassword, user.password());
            verify(userCommandPort, never()).update(anyString(), any(UpdateUserRequest.class));
        }
    }

    @Nested
    class ResendTests {

        @Test
        void resend_shouldSuccessfullyResendCode() throws Exception {
            ArgumentCaptor<CodeCommand> commandArgumentCaptor = ArgumentCaptor.forClass(CodeCommand.class);
            User user = UserDataBuilder.withAllFields().build();

            doNothing().when(codeSender).resend(commandArgumentCaptor.capture(), any(PasswordRecoveryCodeNamespace.class));

            mockMvc.perform(put("/password/resend").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            CodeCommand command = commandArgumentCaptor.getValue();

            assertThat(command).isNotNull();
            assertThat(command.type()).isEqualTo(CodeEventType.PASSWORD_RECOVERY);
            assertThat(command.email()).isEqualTo(user.email());

            verify(userLookupPort).requireExistence(user.email());
            verify(codeSender).resend(eq(command), any(PasswordRecoveryCodeNamespace.class));
        }

        @Test
        void resend_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            doThrow(new UserNotFoundException("User not found.")).when(userLookupPort).requireExistence(user.email());

            String responseContent = mockMvc.perform(put("/password/resend").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isNotFound())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("User not found.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/resend");

            verify(userLookupPort).requireExistence(user.email());
            verify(codeSender, never()).resend(any(CodeCommand.class), any(PasswordRecoveryCodeNamespace.class));
        }

        @Test
        void resend_shouldReturnGone_whenCodeSessionExpired() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            doThrow(new CodeExpiredException("Code session expired.")).when(codeSender).resend(any(CodeCommand.class), any(PasswordRecoveryCodeNamespace.class));

            String responseContent = mockMvc.perform(put("/password/resend").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isGone())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Code session expired.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.GONE.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/resend");

            verify(userLookupPort).requireExistence(user.email());
            verify(codeSender).resend(any(CodeCommand.class), any(PasswordRecoveryCodeNamespace.class));
        }

        @Test
        void resend_shouldReturnConflict_whenCodeAlreadySent() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            doThrow(new CodeAlreadySentException("Code already sent."))
                    .when(codeSender)
                    .resend(any(CodeCommand.class), any(PasswordRecoveryCodeNamespace.class));

            String responseContent = mockMvc.perform(put("/password/resend").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isConflict())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotBlank();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Code already sent.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/password/resend");

            verify(userLookupPort).requireExistence(user.email());
            verify(codeSender).resend(any(CodeCommand.class), any(PasswordRecoveryCodeNamespace.class));
        }
    }
}
