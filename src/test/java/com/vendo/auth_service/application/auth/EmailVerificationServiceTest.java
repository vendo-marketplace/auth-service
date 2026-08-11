package com.vendo.auth_service.application.auth;

import com.vendo.auth_service.adapter.code.out.props.EmailVerificationCodeNamespace;
import com.vendo.auth_service.application.auth.command.CodeCommand;
import com.vendo.auth_service.application.code.CodeSender;
import com.vendo.auth_service.application.code.CodeService;
import com.vendo.auth_service.domain.code.exception.InvalidCodeException;
import com.vendo.auth_service.domain.code.exception.CodeAlreadySentException;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.exception.UserAlreadyVerifiedException;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.event_lib.code.CodeEventType;
import com.vendo.redis_lib.exception.CodeExpiredException;
import com.vendo.user_lib.exception.UserNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailVerificationServiceTest {

    private final String TEST_EMAIL = "email@gmail.com";
    private final String TEST_CODE = "code";
    @InjectMocks
    private EmailVerificationService emailVerificationService;

    @Mock
    private UserQueryPort userQueryPort;
    @Mock
    private CodeSender codeSender;
    @Mock
    private CodeService codeService;
    @Mock
    private EmailVerificationCodeNamespace emailVerificationCodeNamespace;
    @Mock
    private UserCommandPort userCommandPort;

    @Test
    void send_shouldSuccessfullySend_whenUserIsValid() {
        User user = UserDataBuilder.withAllFields().emailVerified(false).build();
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);

        emailVerificationService.send(TEST_EMAIL);

        ArgumentCaptor<CodeCommand> CodeCommandCaptor = ArgumentCaptor.forClass(CodeCommand.class);

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(codeSender).send(CodeCommandCaptor.capture(), eq(emailVerificationCodeNamespace));

        CodeCommand capturedEvent = CodeCommandCaptor.getValue();

        assertThat(capturedEvent.email()).isEqualTo(TEST_EMAIL);
        assertThat(capturedEvent.type()).isEqualTo(CodeEventType.EMAIL_VERIFICATION);
    }

    @Test
    void send_shouldThrowUserAlreadyVerifiedException_whenUserAlreadyVerified() {
        User user = UserDataBuilder.withAllFields().emailVerified(true).build();
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);

        assertThatThrownBy(() -> emailVerificationService.send(TEST_EMAIL))
                .isInstanceOf(UserAlreadyVerifiedException.class)
                .hasMessage("User email is already verified.");

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verifyNoInteractions(codeSender);
    }

    @Test
    void send_shouldThrowUserNotFoundException_whenUserNotFound() {
        doThrow(new UserNotFoundException("User not found.")).when(userQueryPort).getByEmail(TEST_EMAIL);

        assertThatThrownBy(() -> emailVerificationService.send(TEST_EMAIL)).isInstanceOf(UserNotFoundException.class).hasMessage("User not found.");

        verify(userQueryPort).getByEmail(TEST_EMAIL);
    }

    @Test
    void send_shouldThrowCodeAlreadySentException_whenCodeAlreadySent() {
        User user = UserDataBuilder.withAllFields().emailVerified(false).build();
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);
        doThrow(new CodeAlreadySentException("Code already sent.")).when(codeSender).send(any(CodeCommand.class), eq(emailVerificationCodeNamespace));

        assertThatThrownBy(() -> emailVerificationService.send(TEST_EMAIL)).isInstanceOf(CodeAlreadySentException.class).hasMessage("Code already sent.");

        ArgumentCaptor<CodeCommand> argumentCaptor = ArgumentCaptor.forClass(CodeCommand.class);

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(codeSender).send(argumentCaptor.capture(), eq(emailVerificationCodeNamespace));

        CodeCommand capturedEvent = argumentCaptor.getValue();

        assertThat(capturedEvent.email()).isEqualTo(TEST_EMAIL);
        assertThat(capturedEvent.type()).isEqualTo(CodeEventType.EMAIL_VERIFICATION);
    }

    @Test
    void resend_shouldSuccessfullySend_WhenUserIsValid() {
        User user = UserDataBuilder.withAllFields().emailVerified(false).build();
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);

        emailVerificationService.resend(TEST_EMAIL);

        ArgumentCaptor<CodeCommand> CodeCommandCaptor = ArgumentCaptor.forClass(CodeCommand.class);

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(codeSender).resend(CodeCommandCaptor.capture(), eq(emailVerificationCodeNamespace));

        CodeCommand capturedEvent = CodeCommandCaptor.getValue();

        assertThat(capturedEvent.email()).isEqualTo(TEST_EMAIL);
        assertThat(capturedEvent.type()).isEqualTo(CodeEventType.EMAIL_VERIFICATION);
    }

    @Test
    void resend_shouldThrowUserAlreadyVerifiedException_whenUserAlreadyVerified() {
        User user = UserDataBuilder.withAllFields().emailVerified(true).build();
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);

        assertThatThrownBy(() -> emailVerificationService.resend(TEST_EMAIL))
                .isInstanceOf(UserAlreadyVerifiedException.class)
                .hasMessage("User email is already verified.");

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verifyNoInteractions(codeSender);
    }

    @Test
    void resend_shouldThrowUserNotFoundException_whenUserNotFound() {
        doThrow(new UserNotFoundException("User not found.")).when(userQueryPort).getByEmail(TEST_EMAIL);

        assertThatThrownBy(() -> emailVerificationService.resend(TEST_EMAIL)).isInstanceOf(UserNotFoundException.class).hasMessage("User not found.");

        verify(userQueryPort).getByEmail(TEST_EMAIL);
    }

    @Test
    void resend_shouldThrowCodeExpiredException_whenCodeIsExpired() {
        User user = UserDataBuilder.withAllFields().emailVerified(false).build();
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);
        doThrow(new CodeExpiredException("Code session expired.")).when(codeSender).resend(any(CodeCommand.class), eq(emailVerificationCodeNamespace));

        assertThatThrownBy(() -> emailVerificationService.resend(TEST_EMAIL)).isInstanceOf(CodeExpiredException.class).hasMessage("Code session expired.");

        ArgumentCaptor<CodeCommand> CodeCommandCaptor = ArgumentCaptor.forClass(CodeCommand.class);

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(codeSender).resend(CodeCommandCaptor.capture(), eq(emailVerificationCodeNamespace));

        CodeCommand capturedEvent = CodeCommandCaptor.getValue();

        assertThat(capturedEvent.email()).isEqualTo(TEST_EMAIL);
        assertThat(capturedEvent.type()).isEqualTo(CodeEventType.EMAIL_VERIFICATION);
    }

    @Test
    void validate_shouldUpdateUser_WhenUserIsValid() {
        User user = UserDataBuilder.withAllFields().emailVerified(false).build();

        when(codeService.consume(TEST_CODE, emailVerificationCodeNamespace)).thenReturn(user.email());
        when(userQueryPort.getByEmail(user.email())).thenReturn(user);

        emailVerificationService.validate(TEST_CODE);

        verify(codeService).consume(TEST_CODE, emailVerificationCodeNamespace);
        verify(userQueryPort).getByEmail(user.email());
        verify(userCommandPort).update(eq(user.id()), argThat(updatedUser -> updatedUser.emailVerified() == true));
    }

    @Test
    void validate_shouldThrowUserAlreadyVerifiedException_whenUserAlreadyVerified() {
        User user = UserDataBuilder.withAllFields().emailVerified(true).build();

        when(codeService.consume(TEST_CODE, emailVerificationCodeNamespace)).thenReturn(user.email());
        when(userQueryPort.getByEmail(user.email())).thenReturn(user);

        assertThatThrownBy(() -> emailVerificationService.validate(TEST_CODE))
                .isInstanceOf(UserAlreadyVerifiedException.class)
                .hasMessage("User email is already verified.");

        verify(codeService).consume(TEST_CODE, emailVerificationCodeNamespace);
        verify(userQueryPort).getByEmail(user.email());
        verifyNoInteractions(userCommandPort);
    }

    @Test
    void validate_shouldThrowUserNotFoundException_whenUserNotFound() {
        when(codeService.consume(TEST_CODE, emailVerificationCodeNamespace)).thenReturn(TEST_EMAIL);
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenThrow(new UserNotFoundException("User not found."));

        assertThatThrownBy(() -> emailVerificationService.validate(TEST_CODE)).isInstanceOf(UserNotFoundException.class).hasMessage("User not found.");

        verify(codeService).consume(TEST_CODE, emailVerificationCodeNamespace);
        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verifyNoInteractions(userCommandPort);
    }

    @Test
    void validate_shouldThrowInvalidCodeException_whenInvalidCode() {
        User user = UserDataBuilder.withAllFields().build();

        doThrow(new InvalidCodeException("Invalid code.")).when(codeService).consume(TEST_CODE, emailVerificationCodeNamespace);

        assertThatThrownBy(() -> emailVerificationService.validate(TEST_CODE)).isInstanceOf(InvalidCodeException.class).hasMessage("Invalid code.");

        verify(codeService).consume(TEST_CODE, emailVerificationCodeNamespace);
        verify(userQueryPort, never()).getByEmail(user.email());
        verifyNoInteractions(userCommandPort);
    }

}
