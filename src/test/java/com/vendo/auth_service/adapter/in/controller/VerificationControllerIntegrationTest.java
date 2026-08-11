package com.vendo.auth_service.adapter.in.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.auth_service.adapter.code.out.props.EmailVerificationCodeNamespace;
import com.vendo.auth_service.application.auth.command.CodeCommand;
import com.vendo.auth_service.application.auth.dto.UpdateUserRequest;
import com.vendo.auth_service.application.code.CodeSender;
import com.vendo.auth_service.application.code.CodeService;
import com.vendo.auth_service.domain.code.exception.CodeAlreadySentException;
import com.vendo.auth_service.domain.code.exception.TooManyCodeRequestsException;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
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
    private CodeService codeService;
    @MockitoBean
    private CodeSender codeSender;

    @Nested
    class SendTests {

        @Test
        void send_shouldSendEmailVerificationEventSuccessfully() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(false).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            mockMvc.perform(MockMvcRequestBuilders.post("/verification/send").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            ArgumentCaptor<CodeCommand> commandArgumentCaptor = ArgumentCaptor.forClass(CodeCommand.class);
            verify(userQueryPort).getByEmail(user.email());
            verify(codeSender).send(commandArgumentCaptor.capture(), any(EmailVerificationCodeNamespace.class));

            CodeCommand command = commandArgumentCaptor.getValue();
            assertThat(command).isNotNull();
            assertThat(command.email()).isEqualTo(user.email());
            assertThat(command.type()).isEqualTo(CodeEventType.EMAIL_VERIFICATION);
        }

        @Test
        void send_shouldReturnConflict_whenUserAlreadyVerified() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(true).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            String responseContent = mockMvc.perform(post("/verification/send")
                            .contentType(MediaType.APPLICATION_JSON).param("email", user.email()))
                    .andExpect(status().isConflict())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("User email is already verified.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/send");

            verify(userQueryPort).getByEmail(user.email());
            verify(codeSender, never()).send(any(CodeCommand.class), any(EmailVerificationCodeNamespace.class));
        }

        @Test
        void send_shouldReturnConflict_whenEmailVerificationEventHasAlreadySent() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(false).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            ArgumentCaptor<CodeCommand> commandArgumentCaptor = ArgumentCaptor.forClass(CodeCommand.class);
            doThrow(new CodeAlreadySentException("Code already sent."))
                    .when(codeSender)
                    .send(commandArgumentCaptor.capture(), any(EmailVerificationCodeNamespace.class));

            String responseContent = mockMvc.perform(post("/verification/send")
                            .contentType(MediaType.APPLICATION_JSON).param("email", user.email()))
                    .andExpect(status().isConflict())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Code already sent.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/send");

            CodeCommand command = commandArgumentCaptor.getValue();
            assertThat(command).isNotNull();
            assertThat(command.email()).isEqualTo(user.email());
            assertThat(command.type()).isEqualTo(CodeEventType.EMAIL_VERIFICATION);

            verify(userQueryPort).getByEmail(user.email());
            verify(codeSender).send(eq(command), any(EmailVerificationCodeNamespace.class));
        }

        @Test
        void send_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            doThrow(new UserNotFoundException("User not found.")).when(userQueryPort).getByEmail(user.email());

            String responseContent = mockMvc.perform(post("/verification/send")
                            .contentType(MediaType.APPLICATION_JSON).param("email", user.email()))
                    .andExpect(status().isNotFound())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("User not found.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/send");

            verify(userQueryPort).getByEmail(user.email());
            verify(codeSender, never()).send(any(CodeCommand.class), any(EmailVerificationCodeNamespace.class));
        }
    }

    @Nested
    class ResendTests {

        @Test
        void resend_shouldSuccessfullyResend() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(false).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            mockMvc.perform(post("/verification/resend").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            verify(userQueryPort).getByEmail(user.email());
            verify(codeSender).resend(any(CodeCommand.class), any(EmailVerificationCodeNamespace.class));
        }

        @Test
        void resend_shouldReturnConflict_whenUserAlreadyVerified() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(true).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            String responseContent = mockMvc.perform(post("/verification/resend").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isConflict())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("User email is already verified.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.CONFLICT.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/resend");

            verify(userQueryPort).getByEmail(user.email());
            verify(codeSender, never()).resend(any(CodeCommand.class), any(EmailVerificationCodeNamespace.class));
        }

        @Test
        void resend_shouldReturnNotFound_whenUserNotFound() throws Exception {
            User user = UserDataBuilder.withAllFields().build();

            doThrow(new UserNotFoundException("User not found.")).when(userQueryPort).getByEmail(user.email());

            String responseContent = mockMvc.perform(post("/verification/resend").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isNotFound())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("User not found.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/resend");

            verify(userQueryPort).getByEmail(user.email());
            verify(codeSender, never()).resend(any(CodeCommand.class), any(EmailVerificationCodeNamespace.class));
        }

        @Test
        void resend_shouldReturnTooManyRequests_whenTooManyAttempts() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(false).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            doThrow(new TooManyCodeRequestsException("Reached maximum attempts."))
                    .when(codeSender)
                    .resend(any(CodeCommand.class), any(EmailVerificationCodeNamespace.class));

            String responseContent = mockMvc.perform(post("/verification/resend").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isTooManyRequests())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Reached maximum attempts.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/resend");

            verify(userQueryPort).getByEmail(user.email());
            verify(codeSender).resend(any(CodeCommand.class), any(EmailVerificationCodeNamespace.class));
        }

        @Test
        void resend_shouldReturnGone_whenSessionExpired() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(false).build();

            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            doThrow(new CodeExpiredException("Code session expired."))
                    .when(codeSender)
                    .resend(any(CodeCommand.class), any(EmailVerificationCodeNamespace.class));


            String responseContent = mockMvc.perform(post("/verification/resend").param("email", user.email())
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isGone())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Code session expired.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.GONE.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/resend");

            verify(userQueryPort).getByEmail(user.email());
            verify(codeSender).resend(any(CodeCommand.class), any(EmailVerificationCodeNamespace.class));
        }
    }

    @Nested
    class ValidateTests {

        @Test
        void validate_shouldVerifyUser_whenIsValid() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(false).build();
            String code = "123456";

            when(codeService.consume(eq(code), any(EmailVerificationCodeNamespace.class))).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            mockMvc.perform(post("/verification/validate").param("code", code)
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());

            ArgumentCaptor<UpdateUserRequest> updateUserArgumentCaptor = ArgumentCaptor.forClass(UpdateUserRequest.class);
            verify(codeService).consume(eq(code), any(EmailVerificationCodeNamespace.class));
            verify(userQueryPort).getByEmail(user.email());
            verify(userCommandPort).update(eq(user.id()), updateUserArgumentCaptor.capture());

            UpdateUserRequest updateUserArgumentCaptorValue = updateUserArgumentCaptor.getValue();
            assertThat(updateUserArgumentCaptorValue).isNotNull();
            assertThat(updateUserArgumentCaptorValue.emailVerified()).isTrue();
        }

        @Test
        void validate_shouldReturnConflict_whenUserAlreadyVerified() throws Exception {
            User user = UserDataBuilder.withAllFields().emailVerified(true).build();
            String code = "123456";

            when(codeService.consume(eq(code), any(EmailVerificationCodeNamespace.class))).thenReturn(user.email());
            when(userQueryPort.getByEmail(user.email())).thenReturn(user);

            String responseContent = mockMvc.perform(post("/verification/validate").param("code", code)
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

            verify(codeService).consume(eq(code), any(EmailVerificationCodeNamespace.class));
            verify(userQueryPort).getByEmail(user.email());
            verify(userCommandPort, never()).update(eq(user.id()), any(UpdateUserRequest.class));
        }

        @Test
        void validate_shouldReturnGone_whenCodeExpired() throws Exception {
            User user = UserDataBuilder.withAllFields().build();
            String code = "123456";

            doThrow(new CodeExpiredException("Code session expired.")).when(codeService).consume(anyString(), any(EmailVerificationCodeNamespace.class));

            String responseContent = mockMvc.perform(post("/verification/validate").param("code", code)
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isGone())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            assertThat(responseContent).isNotNull();

            ExceptionResponse exceptionResponse = objectMapper.readValue(responseContent, ExceptionResponse.class);
            assertThat(exceptionResponse.getMessage()).isEqualTo("Code session expired.");
            assertThat(exceptionResponse.getCode()).isEqualTo(HttpStatus.GONE.value());
            assertThat(exceptionResponse.getPath()).isEqualTo("/verification/validate");

            verify(codeService).consume(anyString(), any(EmailVerificationCodeNamespace.class));
            verify(userQueryPort, never()).getByEmail(user.email());
            verify(userCommandPort, never()).update(eq(user.id()), any(UpdateUserRequest.class));
        }
    }

}
