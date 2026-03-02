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
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.Mockito.*;

@Slf4j
@MockitoSettings(strictness = Strictness.LENIENT)
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

    @Mock private PrefixProperties emailPrefix;
    @Mock private PrefixProperties otpPrefix;
    @Mock private PrefixProperties attemptsPrefix;

    private final String TEST_EMAIL = "email@gmail.com";
    private final String OLD_OTP = "old-otp";
    private final String TEST_OTP = "otp";

    @BeforeEach
    void setUp() {
        when(otpNamespace.getEmail()).thenReturn(emailPrefix);
        when(otpNamespace.getOtp()).thenReturn(otpPrefix);
        when(otpNamespace.getAttempts()).thenReturn(attemptsPrefix);

        when(emailPrefix.buildPrefix(anyString()))
                .thenAnswer(inv -> "email:" + inv.getArgument(0));
        when(emailPrefix.ttl()).thenReturn(300L);

        when(otpPrefix.buildPrefix(anyString()))
                .thenAnswer(inv -> "otp:" + inv.getArgument(0));
        when(otpPrefix.ttl()).thenReturn(300L);

        when(attemptsPrefix.buildPrefix(anyString()))
                .thenAnswer(inv -> "attempts:" + inv.getArgument(0));
        when(attemptsPrefix.ttl()).thenReturn(300L);
    }

    @Test
    void sendOtp_shouldSuccessfullySendOtp_whenOtpNotSentYet() {
        OtpCommand otpCommand = new OtpCommand(TEST_EMAIL, OtpEventType.EMAIL_VERIFICATION);

        when(otpStorage.hasActiveKey(otpNamespace.getEmail().buildPrefix(otpCommand.email()))).thenReturn(false);
        when(otpGenerator.generate()).thenReturn(TEST_OTP);

        emailOtpService.sendOtp(otpCommand, otpNamespace);

        verify(otpStorage).hasActiveKey(otpNamespace.getEmail().buildPrefix(otpCommand.email()));
        verify(otpGenerator).generate();
        verify(otpStorage).saveValue(
                otpNamespace.getOtp().buildPrefix(TEST_OTP),
                TEST_EMAIL,
                otpNamespace.getOtp().ttl()
        );
        verify(otpStorage).saveValue(
                otpNamespace.getEmail().buildPrefix(TEST_EMAIL),
                TEST_OTP,
                otpNamespace.getEmail().ttl()
        );
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

        when(otpStorage.hasActiveKey(otpNamespace.getEmail().buildPrefix(otpCommand.email()))).thenReturn(true);

        assertThatThrownBy(() -> emailOtpService.sendOtp(otpCommand, otpNamespace)).isInstanceOf(OtpAlreadySentException.class).hasMessage("Otp has already sent.");

        verify(otpStorage).hasActiveKey(otpNamespace.getEmail().buildPrefix(otpCommand.email()));
        verifyNoInteractions(otpGenerator, otpEmailNotificationPort);

        verify(otpStorage, never()).saveValue(anyString(), anyString(), anyLong());
    }

    @Test
    void resendOtp_shouldSuccessfullyResendOtp_whenOldOtpValidAndNoAttempts() {
        OtpCommand otpCommand = new OtpCommand(TEST_EMAIL, OtpEventType.EMAIL_VERIFICATION);

        when(otpStorage.getValue(otpNamespace.getEmail().buildPrefix(otpCommand.email()))).thenReturn(Optional.of(OLD_OTP));
        when(otpStorage.getValue(otpNamespace.getAttempts().buildPrefix(TEST_EMAIL))).thenReturn(Optional.empty());
        when(otpPolicyService.throwOrIncreaseAttempts(0)).thenReturn(1);

        emailOtpService.resendOtp(otpCommand, otpNamespace);

        verify(otpStorage).getValue(otpNamespace.getEmail().buildPrefix(otpCommand.email()));
        verify(otpGenerator, never()).generate();
        verify(otpStorage).saveValue(otpNamespace.getAttempts().buildPrefix(TEST_EMAIL),   String.valueOf(1), otpNamespace.getAttempts().ttl());
        verify(otpEmailNotificationPort).sendOtpEmailNotification(
                argThat(event ->
                        event.email().equals(TEST_EMAIL) &&
                                event.otpEventType() == OtpEventType.EMAIL_VERIFICATION &&
                                event.otp().equals(OLD_OTP)
                )
        );    }
    @Test
    void resendOtp_shouldSuccessfullyResendOtp_whenGenerateOtpAndNoAttempts() {
        OtpCommand otpCommand = new OtpCommand(TEST_EMAIL, OtpEventType.EMAIL_VERIFICATION);

        when(otpStorage.getValue(otpNamespace.getEmail().buildPrefix(otpCommand.email()))).thenReturn(Optional.empty());
        when(otpGenerator.generate()).thenReturn(TEST_OTP);
        when(otpStorage.getValue(otpNamespace.getAttempts().buildPrefix(TEST_EMAIL))).thenReturn(Optional.empty());
        when(otpPolicyService.throwOrIncreaseAttempts(0)).thenReturn(1);


        emailOtpService.resendOtp(otpCommand, otpNamespace);

        verify(otpStorage).getValue(otpNamespace.getEmail().buildPrefix(otpCommand.email()));
        verify(otpGenerator).generate();
        verify(otpStorage).saveValue(otpNamespace.getAttempts().buildPrefix(TEST_EMAIL),   String.valueOf(1), otpNamespace.getAttempts().ttl());
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

        when(otpStorage.getValue(otpNamespace.getEmail().buildPrefix(otpCommand.email()))).thenReturn(Optional.of(OLD_OTP));
        when(otpStorage.getValue(otpNamespace.getAttempts().buildPrefix(TEST_EMAIL))).thenReturn(Optional.of("3"));
        when(otpPolicyService.throwOrIncreaseAttempts(3)).thenThrow(TooManyOtpRequestsException.class);

        assertThatThrownBy(() -> emailOtpService.resendOtp(otpCommand, otpNamespace)).isInstanceOf(TooManyOtpRequestsException.class);

        verify(otpStorage).getValue(otpNamespace.getEmail().buildPrefix(otpCommand.email()));
        verify(otpGenerator, never()).generate();
        verify(otpStorage).getValue(otpNamespace.getAttempts().buildPrefix(TEST_EMAIL));
        verify(otpStorage, never()).saveValue(eq(otpNamespace.getAttempts().buildPrefix(TEST_EMAIL)), anyString(), anyLong());
        verify(otpEmailNotificationPort, never()).sendOtpEmailNotification(any());
        verify(otpGenerator, never()).generate();
        verifyNoMoreInteractions(otpStorage, otpGenerator, otpEmailNotificationPort);
    }
    @Test
    void resendOtp_shouldThrowOtpExpiredException_WhenOtpExpired() {
        OtpCommand otpCommand = new OtpCommand(TEST_EMAIL, OtpEventType.EMAIL_VERIFICATION);

        when(otpStorage.getValue(otpNamespace.getEmail().buildPrefix(otpCommand.email()))).thenThrow(new OtpExpiredException("Otp session expired"));

        assertThatThrownBy(() -> emailOtpService.resendOtp(otpCommand, otpNamespace)).isInstanceOf(OtpExpiredException.class).hasMessage("Otp session expired");

        verify(otpStorage).getValue(otpNamespace.getEmail().buildPrefix(otpCommand.email()));
    }
}
