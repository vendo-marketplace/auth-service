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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.Mockito.*;

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

    private static final String TEST_EMAIL = "email@gmail.com";
    private static final String TEST_OLD_OTP = "old-otp";
    private static final String TEST_OTP = "otp";
    private static final long TEST_TTL = 300L;

    private static final String TEST_OTP_BUILT_PREFIX = "otp:" + TEST_OTP;
    private static final String TEST_EMAIL_BUILT_PREFIX = "email:" + TEST_EMAIL;
    private static final String TEST_ATTEMPTS_BUILT_PREFIX = "attempts:" + TEST_EMAIL;

    @Test
    void sendOtp_shouldSuccessfullySendOtp_whenOtpNotSentYet() {
        OtpCommand otpCommand = new OtpCommand(TEST_EMAIL, OtpEventType.EMAIL_VERIFICATION);

        when(otpNamespace.getEmail()).thenReturn(emailPrefix);
        when(otpNamespace.getOtp()).thenReturn(otpPrefix);

        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_EMAIL_BUILT_PREFIX);
        when(emailPrefix.ttl()).thenReturn(TEST_TTL);

        when(otpPrefix.buildPrefix(TEST_OTP)).thenReturn(TEST_OTP_BUILT_PREFIX);
        when(otpPrefix.ttl()).thenReturn(TEST_TTL);

        when(otpStorage.hasActiveKey(TEST_EMAIL_BUILT_PREFIX)).thenReturn(false);
        when(otpGenerator.generate()).thenReturn(TEST_OTP);

        emailOtpService.sendOtp(otpCommand, otpNamespace);

        verify(otpStorage).hasActiveKey(TEST_EMAIL_BUILT_PREFIX);
        verify(otpGenerator).generate();
        verify(otpStorage).saveValue(TEST_OTP_BUILT_PREFIX, TEST_EMAIL, TEST_TTL);
        verify(otpStorage).saveValue(TEST_EMAIL_BUILT_PREFIX, TEST_OTP, TEST_TTL);
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

        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_EMAIL_BUILT_PREFIX);

        when(otpStorage.hasActiveKey(TEST_EMAIL_BUILT_PREFIX)).thenReturn(true);

        assertThatThrownBy(() -> emailOtpService.sendOtp(otpCommand, otpNamespace)).isInstanceOf(OtpAlreadySentException.class).hasMessage("Otp already sent.");

        verify(otpStorage).hasActiveKey(TEST_EMAIL_BUILT_PREFIX);
        verifyNoInteractions(otpGenerator, otpEmailNotificationPort);

        verify(otpStorage, never()).saveValue(anyString(), anyString(), anyLong());
    }

    @Test
    void resendOtp_shouldSuccessfullyResendOtp_whenOldOtpValidAndNoAttempts() {
        OtpCommand otpCommand = new OtpCommand(TEST_EMAIL, OtpEventType.EMAIL_VERIFICATION);

        when(otpNamespace.getEmail()).thenReturn(emailPrefix);
        when(otpNamespace.getAttempts()).thenReturn(attemptsPrefix);

        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_EMAIL_BUILT_PREFIX);
        when(attemptsPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_ATTEMPTS_BUILT_PREFIX);
        when(attemptsPrefix.ttl()).thenReturn(TEST_TTL);

        when(otpStorage.getValue(TEST_EMAIL_BUILT_PREFIX)).thenReturn(Optional.of(TEST_OLD_OTP));
        when(otpStorage.getValue(TEST_ATTEMPTS_BUILT_PREFIX)).thenReturn(Optional.empty());
        when(otpPolicyService.throwOrIncreaseAttempts(0)).thenReturn(1);

        emailOtpService.resendOtp(otpCommand, otpNamespace);

        verify(otpStorage).getValue(TEST_EMAIL_BUILT_PREFIX);
        verify(otpGenerator, never()).generate();
        verify(otpStorage, never()).saveValue(eq(TEST_EMAIL_BUILT_PREFIX), anyString(), anyLong());
        verify(otpStorage).getValue(TEST_ATTEMPTS_BUILT_PREFIX);
        verify(otpPolicyService).throwOrIncreaseAttempts(0);
        verify(otpStorage).saveValue(TEST_ATTEMPTS_BUILT_PREFIX, "1", TEST_TTL);
        verify(otpEmailNotificationPort).sendOtpEmailNotification(
                argThat(event ->
                        event.email().equals(TEST_EMAIL) &&
                                event.otpEventType() == OtpEventType.EMAIL_VERIFICATION &&
                                event.otp().equals(TEST_OLD_OTP)
                )
        );
    }

    @Test
    void resendOtp_shouldSuccessfullyResendOtp_whenGenerateOtpAndNoAttempts() {
        OtpCommand otpCommand = new OtpCommand(TEST_EMAIL, OtpEventType.EMAIL_VERIFICATION);

        when(otpNamespace.getEmail()).thenReturn(emailPrefix);
        when(otpNamespace.getAttempts()).thenReturn(attemptsPrefix);

        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_EMAIL_BUILT_PREFIX);
        when(otpNamespace.getOtp()).thenReturn(otpPrefix);
        when(otpPrefix.ttl()).thenReturn(TEST_TTL);
        when(attemptsPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_ATTEMPTS_BUILT_PREFIX);
        when(attemptsPrefix.ttl()).thenReturn(TEST_TTL);

        when(otpStorage.getValue(TEST_EMAIL_BUILT_PREFIX)).thenReturn(Optional.empty());
        when(otpStorage.getValue(TEST_ATTEMPTS_BUILT_PREFIX)).thenReturn(Optional.empty());
        when(otpGenerator.generate()).thenReturn(TEST_OTP);
        when(otpPolicyService.throwOrIncreaseAttempts(0)).thenReturn(1);

        emailOtpService.resendOtp(otpCommand, otpNamespace);

        verify(otpStorage).getValue(TEST_EMAIL_BUILT_PREFIX);
        verify(otpGenerator).generate();
        verify(otpStorage).saveValue(TEST_EMAIL_BUILT_PREFIX, TEST_OTP, TEST_TTL);
        verify(otpStorage).getValue(TEST_ATTEMPTS_BUILT_PREFIX);
        verify(otpPolicyService).throwOrIncreaseAttempts(0);
        verify(otpStorage).saveValue(TEST_ATTEMPTS_BUILT_PREFIX, "1", TEST_TTL);
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

        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_EMAIL_BUILT_PREFIX);
        when(attemptsPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_ATTEMPTS_BUILT_PREFIX);

        when(otpStorage.getValue(TEST_EMAIL_BUILT_PREFIX)).thenReturn(Optional.of(TEST_OTP));
        when(otpStorage.getValue(TEST_ATTEMPTS_BUILT_PREFIX)).thenReturn(Optional.of("3"));
        when(otpPolicyService.throwOrIncreaseAttempts(3)).thenThrow(new TooManyOtpRequestsException("Reached maximum attempts."));

        assertThatThrownBy(() -> emailOtpService.resendOtp(otpCommand, otpNamespace)).isInstanceOf(TooManyOtpRequestsException.class).hasMessage("Reached maximum attempts.");

        verify(otpStorage).getValue(TEST_EMAIL_BUILT_PREFIX);
        verify(otpGenerator, never()).generate();
        verify(otpStorage).getValue(TEST_ATTEMPTS_BUILT_PREFIX);
        verify(otpPolicyService).throwOrIncreaseAttempts(3);
        verify(otpStorage, never()).saveValue(eq(TEST_ATTEMPTS_BUILT_PREFIX), anyString(), anyLong());
        verify(otpEmailNotificationPort, never()).sendOtpEmailNotification(any());
        verifyNoMoreInteractions(otpStorage, otpGenerator, otpEmailNotificationPort);
    }

}
