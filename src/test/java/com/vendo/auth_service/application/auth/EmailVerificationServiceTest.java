package com.vendo.auth_service.application.auth;

import com.vendo.auth_service.adapter.otp.out.props.EmailVerificationOtpNamespace;
import com.vendo.auth_service.application.auth.command.OtpCommand;
import com.vendo.auth_service.application.otp.OtpSender;
import com.vendo.auth_service.application.otp.OtpService;
import com.vendo.auth_service.application.otp.common.exception.InvalidOtpException;
import com.vendo.auth_service.application.otp.common.exception.OtpAlreadySentException;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.exception.UserAlreadyVerifiedException;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.event_lib.otp.OtpEventType;
import com.vendo.redis_lib.exception.OtpExpiredException;
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
    private final String TEST_OTP = "otp";
    @InjectMocks
    private EmailVerificationService emailVerificationService;

    @Mock
    private UserQueryPort userQueryPort;
    @Mock
    private OtpSender otpSender;
    @Mock
    private OtpService otpService;
    @Mock
    private EmailVerificationOtpNamespace emailVerificationOtpNamespace;
    @Mock
    private UserCommandPort userCommandPort;

    @Test
    void sendOtp_shouldSuccessfullySendOtp_whenUserIsValid() {
        User user = UserDataBuilder.withAllFields().emailVerified(false).build();
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);

        emailVerificationService.sendOtp(TEST_EMAIL);

        ArgumentCaptor<OtpCommand> OtpCommandCaptor = ArgumentCaptor.forClass(OtpCommand.class);

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(otpSender).sendOtp(OtpCommandCaptor.capture(), eq(emailVerificationOtpNamespace));

        OtpCommand capturedEvent = OtpCommandCaptor.getValue();

        assertThat(capturedEvent.email()).isEqualTo(TEST_EMAIL);
        assertThat(capturedEvent.type()).isEqualTo(OtpEventType.EMAIL_VERIFICATION);
    }

    @Test
    void sendOtp_shouldThrowUserAlreadyVerifiedException_whenUserAlreadyVerified() {
        User user = UserDataBuilder.withAllFields().emailVerified(true).build();
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);

        assertThatThrownBy(() -> emailVerificationService.sendOtp(TEST_EMAIL))
                .isInstanceOf(UserAlreadyVerifiedException.class)
                .hasMessage("User email is already verified.");

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verifyNoInteractions(otpSender);
    }

    @Test
    void sendOtp_shouldThrowUserNotFoundException_whenUserNotFound() {
        doThrow(new UserNotFoundException("User not found.")).when(userQueryPort).getByEmail(TEST_EMAIL);

        assertThatThrownBy(() -> emailVerificationService.sendOtp(TEST_EMAIL)).isInstanceOf(UserNotFoundException.class).hasMessage("User not found.");

        verify(userQueryPort).getByEmail(TEST_EMAIL);
    }

    @Test
    void sendOtp_shouldThrowOtpAlreadySentException_whenOtpAlreadySent() {
        User user = UserDataBuilder.withAllFields().emailVerified(false).build();
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);
        doThrow(new OtpAlreadySentException("Otp already sent.")).when(otpSender).sendOtp(any(OtpCommand.class), eq(emailVerificationOtpNamespace));

        assertThatThrownBy(() -> emailVerificationService.sendOtp(TEST_EMAIL)).isInstanceOf(OtpAlreadySentException.class).hasMessage("Otp already sent.");

        ArgumentCaptor<OtpCommand> OtpCommandCaptor = ArgumentCaptor.forClass(OtpCommand.class);

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(otpSender).sendOtp(OtpCommandCaptor.capture(), eq(emailVerificationOtpNamespace));

        OtpCommand capturedEvent = OtpCommandCaptor.getValue();

        assertThat(capturedEvent.email()).isEqualTo(TEST_EMAIL);
        assertThat(capturedEvent.type()).isEqualTo(OtpEventType.EMAIL_VERIFICATION);
    }

    @Test
    void resendOtp_shouldSuccessfullySendOtp_WhenUserIsValid() {
        User user = UserDataBuilder.withAllFields().emailVerified(false).build();
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);

        emailVerificationService.resendOtp(TEST_EMAIL);

        ArgumentCaptor<OtpCommand> OtpCommandCaptor = ArgumentCaptor.forClass(OtpCommand.class);

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(otpSender).resendOtp(OtpCommandCaptor.capture(), eq(emailVerificationOtpNamespace));

        OtpCommand capturedEvent = OtpCommandCaptor.getValue();

        assertThat(capturedEvent.email()).isEqualTo(TEST_EMAIL);
        assertThat(capturedEvent.type()).isEqualTo(OtpEventType.EMAIL_VERIFICATION);
    }

    @Test
    void resendOtp_shouldThrowUserAlreadyVerifiedException_whenUserAlreadyVerified() {
        User user = UserDataBuilder.withAllFields().emailVerified(true).build();
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);

        assertThatThrownBy(() -> emailVerificationService.resendOtp(TEST_EMAIL))
                .isInstanceOf(UserAlreadyVerifiedException.class)
                .hasMessage("User email is already verified.");

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verifyNoInteractions(otpSender);
    }

    @Test
    void resendOtp_shouldThrowUserNotFoundException_whenUserNotFound() {
        doThrow(new UserNotFoundException("User not found.")).when(userQueryPort).getByEmail(TEST_EMAIL);

        assertThatThrownBy(() -> emailVerificationService.resendOtp(TEST_EMAIL)).isInstanceOf(UserNotFoundException.class).hasMessage("User not found.");

        verify(userQueryPort).getByEmail(TEST_EMAIL);
    }

    @Test
    void resendOtp_shouldThrowOtpExpiredException_whenOtpIsExpired() {
        User user = UserDataBuilder.withAllFields().emailVerified(false).build();
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);
        doThrow(new OtpExpiredException("Otp session expired.")).when(otpSender).resendOtp(any(OtpCommand.class), eq(emailVerificationOtpNamespace));

        assertThatThrownBy(() -> emailVerificationService.resendOtp(TEST_EMAIL)).isInstanceOf(OtpExpiredException.class).hasMessage("Otp session expired.");

        ArgumentCaptor<OtpCommand> OtpCommandCaptor = ArgumentCaptor.forClass(OtpCommand.class);

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(otpSender).resendOtp(OtpCommandCaptor.capture(), eq(emailVerificationOtpNamespace));

        OtpCommand capturedEvent = OtpCommandCaptor.getValue();

        assertThat(capturedEvent.email()).isEqualTo(TEST_EMAIL);
        assertThat(capturedEvent.type()).isEqualTo(OtpEventType.EMAIL_VERIFICATION);
    }

    @Test
    void validate_shouldUpdateUser_WhenUserIsValid() {
        User user = UserDataBuilder.withAllFields().emailVerified(false).build();

        when(otpService.verify(TEST_OTP, emailVerificationOtpNamespace)).thenReturn(user.email());
        when(userQueryPort.getByEmail(user.email())).thenReturn(user);

        emailVerificationService.validate(TEST_OTP);

        verify(otpService).verify(TEST_OTP, emailVerificationOtpNamespace);
        verify(userQueryPort).getByEmail(user.email());
        verify(userCommandPort).update(eq(user.id()), argThat(updatedUser -> updatedUser.emailVerified() == true));
    }

    @Test
    void validate_shouldThrowUserAlreadyVerifiedException_whenUserAlreadyVerified() {
        User user = UserDataBuilder.withAllFields().emailVerified(true).build();

        when(otpService.verify(TEST_OTP, emailVerificationOtpNamespace)).thenReturn(user.email());
        when(userQueryPort.getByEmail(user.email())).thenReturn(user);

        assertThatThrownBy(() -> emailVerificationService.validate(TEST_OTP))
                .isInstanceOf(UserAlreadyVerifiedException.class)
                .hasMessage("User email is already verified.");

        verify(otpService).verify(TEST_OTP, emailVerificationOtpNamespace);
        verify(userQueryPort).getByEmail(user.email());
        verifyNoInteractions(userCommandPort);
    }

    @Test
    void validate_shouldThrowUserNotFoundException_whenUserNotFound() {
        when(otpService.verify(TEST_OTP, emailVerificationOtpNamespace)).thenReturn(TEST_EMAIL);
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenThrow(new UserNotFoundException("User not found."));

        assertThatThrownBy(() -> emailVerificationService.validate(TEST_OTP)).isInstanceOf(UserNotFoundException.class).hasMessage("User not found.");

        verify(otpService).verify(TEST_OTP, emailVerificationOtpNamespace);
        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verifyNoInteractions(userCommandPort);
    }

    @Test
    void validate_shouldThrowInvalidOtpException_whenInvalidOtp() {
        User user = UserDataBuilder.withAllFields().build();

        doThrow(new InvalidOtpException("Invalid otp.")).when(otpService).verify(TEST_OTP, emailVerificationOtpNamespace);

        assertThatThrownBy(() -> emailVerificationService.validate(TEST_OTP)).isInstanceOf(InvalidOtpException.class).hasMessage("Invalid otp.");

        verify(otpService).verify(TEST_OTP, emailVerificationOtpNamespace);
        verify(userQueryPort, never()).getByEmail(user.email());
        verifyNoInteractions(userCommandPort);
    }

}
