package com.vendo.auth_service.application.otp;

import com.vendo.auth_service.adapter.otp.out.props.OtpNamespace;
import com.vendo.auth_service.application.auth.command.OtpCommand;
import com.vendo.auth_service.application.otp.common.exception.OtpAlreadySentException;
import com.vendo.auth_service.application.otp.common.exception.TooManyOtpRequestsException;
import com.vendo.auth_service.domain.otp.OtpPolicyService;
import com.vendo.auth_service.port.otp.OtpEmailNotificationPort;
import com.vendo.auth_service.port.otp.OtpGenerator;
import com.vendo.auth_service.port.otp.OtpStorage;
import com.vendo.event_lib.OtpEventType;
import com.vendo.redis_lib.config.PrefixProperties;
import com.vendo.redis_lib.exception.OtpExpiredException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.Mockito.*;

@Slf4j
@ExtendWith(MockitoExtension.class)
public class EmailOtpServiceTest {

    @InjectMocks
    EmailOtpService emailOtpService;

    @Mock
    private OtpGenerator otpGenerator;
    @Mock
    private OtpStorage otpStorage;
    @Mock
    private OtpEmailNotificationPort otpEmailNotificationPort;
    @Mock
    private OtpNamespace otpNamespace;
    @Mock
    private OtpPolicyService otpPolicyService;

    @Mock
    private PrefixProperties emailPrefix;
    @Mock
    private PrefixProperties otpPrefix;
    @Mock
    private PrefixProperties attemptsPrefix;

    private final String TEST_EMAIL = "email@gmail.com";
    private final String OLD_OTP = "old-otp";
    private final String TEST_OTP = "otp";

    @Test
    void sendOtp_shouldSuccessfullySendOtp_whenOtpNotSentYet() {
        OtpCommand otpCommand = new OtpCommand(TEST_EMAIL, OtpEventType.EMAIL_VERIFICATION);

        when(otpNamespace.getEmail()).thenReturn(emailPrefix);
        when(otpNamespace.getOtp()).thenReturn(otpPrefix);

        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn("email:" + TEST_EMAIL);
        when(emailPrefix.ttl()).thenReturn(300L);

        when(otpPrefix.buildPrefix(TEST_OTP)).thenReturn("otp:" + TEST_OTP);
        when(otpPrefix.ttl()).thenReturn(300L);

        when(otpStorage.hasActiveKey("email:" + TEST_EMAIL)).thenReturn(false);
        when(otpGenerator.generate()).thenReturn(TEST_OTP);

        emailOtpService.sendOtp(otpCommand, otpNamespace);

        verify(otpStorage).hasActiveKey("email:" + TEST_EMAIL);
        verify(otpGenerator).generate();
        verify(otpStorage).saveValue("otp:" + TEST_OTP, TEST_EMAIL, 300L);
        verify(otpStorage).saveValue("email:" + TEST_EMAIL, TEST_OTP, 300L);
        verify(otpEmailNotificationPort).sendOtpEmailNotification(
                argThat(event ->
                        event.email().equals(TEST_EMAIL) &&
                                event.otpEventType() == OtpEventType.EMAIL_VERIFICATION &&
                                event.otp().equals(TEST_OTP)
                )
        );
    }

    @Test
    void sendOtp_shouldThrowOtpAlreadySentException_whenOtpAlreadySent() {
        OtpCommand otpCommand = new OtpCommand(TEST_EMAIL, OtpEventType.EMAIL_VERIFICATION);

        when(otpNamespace.getEmail()).thenReturn(emailPrefix);

        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn("email:" + TEST_EMAIL);

        when(otpStorage.hasActiveKey("email:" + TEST_EMAIL)).thenReturn(true);

        assertThatThrownBy(() -> emailOtpService.sendOtp(otpCommand, otpNamespace)).isInstanceOf(OtpAlreadySentException.class).hasMessage("Otp has already sent.");

        verify(otpStorage).hasActiveKey("email:" + TEST_EMAIL);
        verifyNoInteractions(otpGenerator, otpEmailNotificationPort);

        verify(otpStorage, never()).saveValue(anyString(), anyString(), anyLong());
    }

    @Test
    void resendOtp_shouldSuccessfullyResendOtp_whenOldOtpValidAndNoAttempts() {
        OtpCommand otpCommand = new OtpCommand(TEST_EMAIL, OtpEventType.EMAIL_VERIFICATION);

        when(otpNamespace.getEmail()).thenReturn(emailPrefix);
        when(otpNamespace.getAttempts()).thenReturn(attemptsPrefix);

        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn("email:" + TEST_EMAIL);
        when(attemptsPrefix.buildPrefix(TEST_EMAIL)).thenReturn("attempts:" + TEST_EMAIL);
        when(attemptsPrefix.ttl()).thenReturn(300L);

        when(otpStorage.getValue("email:" + TEST_EMAIL)).thenReturn(Optional.of(OLD_OTP));
        when(otpStorage.getValue("attempts:" + TEST_EMAIL)).thenReturn(Optional.empty());
        when(otpPolicyService.throwOrIncreaseAttempts(0)).thenReturn(1);

        emailOtpService.resendOtp(otpCommand, otpNamespace);

        verify(otpStorage).getValue("email:" + TEST_EMAIL);
        verify(otpGenerator, never()).generate();
        verify(otpStorage).saveValue("attempts:" + TEST_EMAIL, "1", 300L);
        verify(otpEmailNotificationPort).sendOtpEmailNotification(
                argThat(event ->
                        event.email().equals(TEST_EMAIL) &&
                                event.otpEventType() == OtpEventType.EMAIL_VERIFICATION &&
                                event.otp().equals(OLD_OTP)
                )
        );
    }

    @Test
    void resendOtp_shouldSuccessfullyResendOtp_whenGenerateOtpAndNoAttempts() {
        OtpCommand otpCommand = new OtpCommand(TEST_EMAIL, OtpEventType.EMAIL_VERIFICATION);

        when(otpNamespace.getEmail()).thenReturn(emailPrefix);
        when(otpNamespace.getAttempts()).thenReturn(attemptsPrefix);

        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn("email:" + TEST_EMAIL);
        when(otpNamespace.getOtp()).thenReturn(otpPrefix);
        when(otpPrefix.ttl()).thenReturn(300L);
        when(attemptsPrefix.buildPrefix(TEST_EMAIL)).thenReturn("attempts:" + TEST_EMAIL);
        when(attemptsPrefix.ttl()).thenReturn(300L);

        when(otpStorage.getValue("email:" + TEST_EMAIL)).thenReturn(Optional.empty());
        when(otpStorage.getValue("attempts:" + TEST_EMAIL)).thenReturn(Optional.empty());
        when(otpGenerator.generate()).thenReturn(TEST_OTP);
        when(otpPolicyService.throwOrIncreaseAttempts(0)).thenReturn(1);

        emailOtpService.resendOtp(otpCommand, otpNamespace);

        verify(otpStorage).getValue("email:" + TEST_EMAIL);
        verify(otpGenerator).generate();
        verify(otpStorage).saveValue("attempts:" + TEST_EMAIL, "1", 300L);
        verify(otpEmailNotificationPort).sendOtpEmailNotification(
                argThat(event ->
                        event.email().equals(TEST_EMAIL) &&
                                event.otpEventType() == OtpEventType.EMAIL_VERIFICATION &&
                                event.otp().equals(TEST_OTP)
                )
        );
    }
    @Test
    void resendOtp_shouldThrowTooManyOtpRequestsException_whenOtpValidAndExceededAttempts() {
        OtpCommand otpCommand = new OtpCommand(TEST_EMAIL, OtpEventType.EMAIL_VERIFICATION);

        when(otpNamespace.getEmail()).thenReturn(emailPrefix);
        when(otpNamespace.getAttempts()).thenReturn(attemptsPrefix);

        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn("email:" + TEST_EMAIL);
        when(attemptsPrefix.buildPrefix(TEST_EMAIL)).thenReturn("attempts:" + TEST_EMAIL);

        when(otpStorage.getValue("email:" + TEST_EMAIL)).thenReturn(Optional.of(TEST_OTP));
        when(otpStorage.getValue("attempts:" + TEST_EMAIL)).thenReturn(Optional.of("3"));
        when(otpPolicyService.throwOrIncreaseAttempts(3)).thenThrow(TooManyOtpRequestsException.class);

        assertThatThrownBy(() -> emailOtpService.resendOtp(otpCommand, otpNamespace)).isInstanceOf(TooManyOtpRequestsException.class);

        verify(otpStorage).getValue("email:" + TEST_EMAIL);
        verify(otpGenerator, never()).generate();
        verify(otpStorage).getValue("attempts:" + TEST_EMAIL);
        verify(otpStorage, never()).saveValue(eq("attempts:" + TEST_EMAIL), anyString(), anyLong());
        verify(otpEmailNotificationPort, never()).sendOtpEmailNotification(any());
        verify(otpGenerator, never()).generate();
        verifyNoMoreInteractions(otpStorage, otpGenerator, otpEmailNotificationPort);
    }

    @Test
    void resendOtp_shouldThrowOtpExpiredException_WhenOtpExpired() {
        OtpCommand otpCommand = new OtpCommand(TEST_EMAIL, OtpEventType.EMAIL_VERIFICATION);

        when(otpNamespace.getEmail()).thenReturn(emailPrefix);

        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn("email:" + TEST_EMAIL);

        when(otpStorage.getValue("email:" + TEST_EMAIL)).thenThrow(new OtpExpiredException("Otp session expired"));

        assertThatThrownBy(() -> emailOtpService.resendOtp(otpCommand, otpNamespace)).isInstanceOf(OtpExpiredException.class).hasMessage("Otp session expired");

        verify(otpStorage).getValue("email:" + TEST_EMAIL);
    }
}
