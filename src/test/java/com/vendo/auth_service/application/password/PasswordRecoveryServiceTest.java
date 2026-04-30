package com.vendo.auth_service.application.password;

import com.vendo.auth_service.adapter.otp.out.props.PasswordRecoveryOtpNamespace;
import com.vendo.auth_service.application.auth.command.OtpCommand;
import com.vendo.auth_service.application.otp.OtpVerifier;
import com.vendo.auth_service.application.otp.OtpService;
import com.vendo.auth_service.application.otp.common.exception.InvalidOtpException;
import com.vendo.auth_service.application.otp.common.exception.OtpAlreadySentException;
import com.vendo.auth_service.application.password.command.ResetPasswordCommand;
import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.event_lib.otp.OtpEventType;
import com.vendo.user_lib.exception.UserNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class PasswordRecoveryServiceTest {

    @InjectMocks
    PasswordRecoveryService passwordRecoveryService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private PasswordRecoveryOtpNamespace passwordRecoveryOtpNamespace;
    @Mock
    private UserQueryPort userQueryPort;
    @Mock
    private UserCommandPort userCommandPort;
    @Mock
    private OtpService otpService;
    @Mock
    private OtpVerifier otpVerifier;

    private final String TEST_EMAIL = "email@gmail.com";
    private final String TEST_OTP = "otp";
    private final String TEST_PASSWORD = "password";


    @Test
    void forgotPassword_shouldSendOtp_WhenUserValid() {
        User user = UserDataBuilder.withAllFields().email(TEST_EMAIL).build();

        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);

        passwordRecoveryService.forgotPassword(TEST_EMAIL);

        ArgumentCaptor<OtpCommand> otpCommandArgumentCaptor = ArgumentCaptor.forClass(OtpCommand.class);

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(otpService).sendOtp(otpCommandArgumentCaptor.capture(), eq(passwordRecoveryOtpNamespace));

        OtpCommand capturedCommand = otpCommandArgumentCaptor.getValue();

        assertThat(capturedCommand.email()).isEqualTo(TEST_EMAIL);
        assertThat(capturedCommand.type()).isEqualTo(OtpEventType.PASSWORD_RECOVERY);
    }
    @Test
    void forgotPassword_shouldThrowUserNotFoundException_WhenUserNotFound() {
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenThrow(new UserNotFoundException("User not found."));

        assertThatThrownBy(() -> passwordRecoveryService.forgotPassword(TEST_EMAIL)).isInstanceOf(UserNotFoundException.class).hasMessage("User not found.");

        verify(userQueryPort).getByEmail(TEST_EMAIL);
    }

    @Test
    void forgotPassword_shouldThrowOtpAlreadySentException_whenOtpAlreadySent() {
        User user = UserDataBuilder.withAllFields().email(TEST_EMAIL).build();

        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);
        doThrow(new OtpAlreadySentException("Otp already sent.")).when(otpService).sendOtp(any(OtpCommand.class), eq(passwordRecoveryOtpNamespace));

        assertThatThrownBy(() -> passwordRecoveryService.forgotPassword(TEST_EMAIL)).isInstanceOf(OtpAlreadySentException.class).hasMessage("Otp already sent.");

        ArgumentCaptor<OtpCommand> otpCommandArgumentCaptor = ArgumentCaptor.forClass(OtpCommand.class);

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(otpService).sendOtp(otpCommandArgumentCaptor.capture(), eq(passwordRecoveryOtpNamespace));

        OtpCommand capturedEvent = otpCommandArgumentCaptor.getValue();

        assertThat(capturedEvent.email()).isEqualTo(TEST_EMAIL);
        assertThat(capturedEvent.type()).isEqualTo(OtpEventType.PASSWORD_RECOVERY);
    }

    @Test
    void resetPassword_shouldResetPassword_whenUserAndOtpAreValid() {
        String encodedPassword = "encodedPassword";
        ResetPasswordCommand resetPasswordCommand = new ResetPasswordCommand(TEST_PASSWORD);
        User user = UserDataBuilder.withAllFields().email(TEST_EMAIL).build();

        when(otpVerifier.verify(TEST_OTP, passwordRecoveryOtpNamespace)).thenReturn(TEST_EMAIL);
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);
        when(passwordEncoder.encode(TEST_PASSWORD)).thenReturn(encodedPassword);

        passwordRecoveryService.resetPassword(TEST_OTP, resetPasswordCommand);

        verify(otpVerifier).verify(TEST_OTP, passwordRecoveryOtpNamespace);
        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(userCommandPort).update(eq(user.id()), argThat(updatedUser -> encodedPassword.equals(updatedUser.password())));
    }

    @Test
    void resetPassword_shouldThrowInvalidOtpException_whenInvalidOtp() {
        ResetPasswordCommand resetPasswordCommand = new ResetPasswordCommand(TEST_PASSWORD);

        when(otpVerifier.verify(TEST_OTP, passwordRecoveryOtpNamespace)).thenThrow(new InvalidOtpException("Invalid otp"));

        assertThatThrownBy(() -> passwordRecoveryService.resetPassword(TEST_OTP, resetPasswordCommand)).isInstanceOf(InvalidOtpException.class).hasMessage("Invalid otp");

        verify(otpVerifier).verify(TEST_OTP, passwordRecoveryOtpNamespace);
    }

    @Test
    void resetPassword_shouldThrowUserNotFoundException_whenUserNotFound() {
        ResetPasswordCommand resetPasswordCommand = new ResetPasswordCommand(TEST_PASSWORD);

        when(otpVerifier.verify(TEST_OTP, passwordRecoveryOtpNamespace)).thenReturn(TEST_EMAIL);
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenThrow(new UserNotFoundException("User not found."));

        assertThatThrownBy(() -> passwordRecoveryService.resetPassword(TEST_OTP, resetPasswordCommand)).isInstanceOf(UserNotFoundException.class).hasMessage("User not found.");

        verify(otpVerifier).verify(TEST_OTP, passwordRecoveryOtpNamespace);
        verify(userQueryPort).getByEmail(TEST_EMAIL);
    }

    @Test
    void resendOtp_shouldSuccessfullySendOtp_whenUserIsValid() {
        User user = UserDataBuilder.withAllFields().email(TEST_EMAIL).build();

        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);

        passwordRecoveryService.resendOtp(TEST_EMAIL);

        ArgumentCaptor<OtpCommand> otpCommandArgumentCaptor = ArgumentCaptor.forClass(OtpCommand.class);

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(otpService).resendOtp(otpCommandArgumentCaptor.capture(), eq(passwordRecoveryOtpNamespace));

        OtpCommand capturedEvent = otpCommandArgumentCaptor.getValue();

        assertThat(capturedEvent.email()).isEqualTo(TEST_EMAIL);
        assertThat(capturedEvent.type()).isEqualTo(OtpEventType.PASSWORD_RECOVERY);
    }
    @Test
    void resendOtp_shouldThrowUserNotFoundException_whenUserNotFound() {
        when(userQueryPort.getByEmail(TEST_EMAIL)).thenThrow(new UserNotFoundException("User not found."));

        assertThatThrownBy(() -> passwordRecoveryService.resendOtp(TEST_EMAIL)).isInstanceOf(UserNotFoundException.class).hasMessage("User not found.");

        verify(userQueryPort).getByEmail(TEST_EMAIL);
    }
    @Test
    void resendOtp_shouldThrowOtpAlreadySentException_whenOtpAlreadySent() {
        User user = UserDataBuilder.withAllFields().email(TEST_EMAIL).build();

        when(userQueryPort.getByEmail(TEST_EMAIL)).thenReturn(user);
        doThrow(new OtpAlreadySentException("Otp already sent.")).when(otpService).resendOtp(any(OtpCommand.class), eq(passwordRecoveryOtpNamespace));

        assertThatThrownBy(() -> passwordRecoveryService.resendOtp(TEST_EMAIL)).isInstanceOf(OtpAlreadySentException.class).hasMessage("Otp already sent.");

        ArgumentCaptor<OtpCommand> otpCommandArgumentCaptor = ArgumentCaptor.forClass(OtpCommand.class);

        verify(userQueryPort).getByEmail(TEST_EMAIL);
        verify(otpService).resendOtp(otpCommandArgumentCaptor.capture(), eq(passwordRecoveryOtpNamespace));

        OtpCommand capturedEvent = otpCommandArgumentCaptor.getValue();

        assertThat(capturedEvent.email()).isEqualTo(TEST_EMAIL);
        assertThat(capturedEvent.type()).isEqualTo(OtpEventType.PASSWORD_RECOVERY);
    }

}
