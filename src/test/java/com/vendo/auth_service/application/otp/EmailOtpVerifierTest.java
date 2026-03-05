package com.vendo.auth_service.application.otp;

import com.vendo.auth_service.adapter.otp.out.props.OtpNamespace;
import com.vendo.auth_service.application.otp.common.exception.InvalidOtpException;
import com.vendo.auth_service.port.otp.OtpStorage;
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
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.*;


@Slf4j
@MockitoSettings(strictness = Strictness.LENIENT)
@ExtendWith(MockitoExtension.class)
public class EmailOtpVerifierTest {
    @InjectMocks
    EmailOtpVerifier emailOtpVerifier;
    @Mock
    OtpStorage otpStorage;
    @Mock
    OtpNamespace otpNamespace;

    @Mock private PrefixProperties emailPrefix;
    @Mock private PrefixProperties otpPrefix;
    @Mock private PrefixProperties attemptsPrefix;

    private static final String TEST_EMAIL = "email@gmail.com";
    private static final String TEST_OTP = "otp";

    @BeforeEach
    void setUp() {
        when(otpNamespace.getEmail()).thenReturn(emailPrefix);
        when(otpNamespace.getOtp()).thenReturn(otpPrefix);
        when(otpNamespace.getAttempts()).thenReturn(attemptsPrefix);

        when(emailPrefix.buildPrefix(anyString()))
                .thenAnswer(inv -> "email:" + inv.getArgument(0));
        when(otpPrefix.buildPrefix(anyString()))
                .thenAnswer(inv -> "otp:" + inv.getArgument(0));
        when(attemptsPrefix.buildPrefix(anyString()))
                .thenAnswer(inv -> "attempts:" + inv.getArgument(0));
    }

    @Test
    void verify_shouldReturnEmail_whenOtpValid() {
        when(otpStorage.getValue(otpNamespace.getOtp().buildPrefix(TEST_OTP))).thenReturn(Optional.of(TEST_EMAIL));

        emailOtpVerifier.verify(TEST_OTP, otpNamespace);

        verify(otpStorage).getValue(otpNamespace.getOtp().buildPrefix(TEST_OTP));
        verify(otpStorage).deleteValues(otpNamespace.getOtp().buildPrefix(TEST_OTP));
    }
    @Test
    void verify_shouldThrowOtpExpiredException_whenOtpExpired() {
        when(otpStorage.getValue(otpNamespace.getOtp().buildPrefix(TEST_OTP))).thenReturn(Optional.empty()).thenThrow(new OtpExpiredException("Otp session expired."));

        assertThatThrownBy(() -> emailOtpVerifier.verify(TEST_OTP, otpNamespace)).isInstanceOf(OtpExpiredException.class).hasMessage("Otp session expired.");

        verify(otpStorage).getValue(otpNamespace.getOtp().buildPrefix(TEST_OTP));
    }
    @Test
    void verifyOtpEmail_shouldCleanUpOtpNamespaces_whenEmailsMatch() {
        String actualEmail = TEST_EMAIL;
        when(otpStorage.getValue(otpNamespace.getOtp().buildPrefix(TEST_OTP))).thenReturn(Optional.of(actualEmail));

        emailOtpVerifier.verifyOtpEmail(TEST_OTP, TEST_EMAIL, otpNamespace);

        verify(otpStorage).getValue(otpNamespace.getOtp().buildPrefix(TEST_OTP));
        verify(otpStorage).deleteValues(
                otpNamespace.getOtp().buildPrefix(TEST_OTP),
                otpNamespace.getEmail().buildPrefix(actualEmail),
                otpNamespace.getAttempts().buildPrefix(actualEmail)
        );
    }
    @Test
    void verifyOtpEmail_shouldThrowOtpExpiredException_whenOtpExpired() {
        when(otpStorage.getValue(otpNamespace.getOtp().buildPrefix(TEST_OTP))).thenReturn(Optional.empty()).thenThrow(new OtpExpiredException("Otp session expired."));

        assertThatThrownBy(() -> emailOtpVerifier.verifyOtpEmail(TEST_OTP, TEST_EMAIL, otpNamespace)).isInstanceOf(OtpExpiredException.class).hasMessage("Otp session expired.");

        verify(otpStorage).getValue(otpNamespace.getOtp().buildPrefix(TEST_OTP));
    }
    @Test
    void verifyOtpEmail_shouldThrowInvalidOtpException_whenEmailsNotMatch() {
        String actualEmail = "actual@gmail.com";

        when(otpStorage.getValue(otpNamespace.getOtp().buildPrefix(TEST_OTP))).thenReturn(Optional.of(actualEmail));

        assertThatThrownBy(() -> emailOtpVerifier.verifyOtpEmail(TEST_OTP, TEST_EMAIL, otpNamespace)).isInstanceOf(InvalidOtpException.class).hasMessage("Invalid otp.");

        assertThat(!TEST_EMAIL.equals(actualEmail));

        verify(otpStorage).getValue(otpNamespace.getOtp().buildPrefix(TEST_OTP));
        verify(otpStorage, never()).deleteValues(
                otpNamespace.getOtp().buildPrefix(TEST_OTP),
                otpNamespace.getEmail().buildPrefix(actualEmail),
                otpNamespace.getAttempts().buildPrefix(actualEmail)
        );
    }
}
