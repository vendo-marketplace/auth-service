package com.vendo.auth_service.application.otp;

import com.vendo.auth_service.adapter.otp.out.props.OtpNamespace;
import com.vendo.auth_service.port.otp.OtpStorage;
import com.vendo.redis_lib.config.PrefixProperties;
import com.vendo.redis_lib.exception.OtpExpiredException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class EmailOtpVerifierTest {

    private static final String TEST_EMAIL = "email@gmail.com";
    private static final String TEST_OTP = "otp";
    private static final String TEST_OTP_BUILT_PREFIX = "otp:" + TEST_OTP;
    private static final String TEST_EMAIL_BUILT_PREFIX = "email:" + TEST_EMAIL;
    private static final String TEST_ATTEMPTS_BUILT_PREFIX = "attempts:" + TEST_EMAIL;

    @InjectMocks
    private EmailOtpVerifier emailOtpVerifier;

    @Mock
    private OtpStorage otpStorage;
    @Mock
    private OtpNamespace otpNamespace;
    @Mock
    private PrefixProperties emailPrefix;
    @Mock
    private PrefixProperties otpPrefix;
    @Mock
    private PrefixProperties attemptsPrefix;

    @Test
    void verify_shouldReturnEmail_whenOtpValid() {
        when(otpNamespace.getOtp()).thenReturn(otpPrefix);
        when(otpNamespace.getEmail()).thenReturn(emailPrefix);
        when(otpNamespace.getAttempts()).thenReturn(attemptsPrefix);
        when(otpPrefix.buildPrefix(TEST_OTP)).thenReturn(TEST_OTP_BUILT_PREFIX);
        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_EMAIL_BUILT_PREFIX);
        when(attemptsPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_ATTEMPTS_BUILT_PREFIX);

        when(otpStorage.getValue(TEST_OTP_BUILT_PREFIX)).thenReturn(Optional.of(TEST_EMAIL));

        emailOtpVerifier.verify(TEST_OTP, otpNamespace);

        verify(otpStorage).getValue(TEST_OTP_BUILT_PREFIX);
        verify(otpStorage).deleteValues(
                TEST_OTP_BUILT_PREFIX,
                TEST_EMAIL_BUILT_PREFIX,
                TEST_ATTEMPTS_BUILT_PREFIX
        );
    }

    @Test
    void verify_shouldThrowOtpExpiredException_whenOtpExpired() {
        when(otpNamespace.getOtp()).thenReturn(otpPrefix);
        when(otpPrefix.buildPrefix(TEST_OTP)).thenReturn(TEST_OTP_BUILT_PREFIX);
        when(otpStorage.getValue(TEST_OTP_BUILT_PREFIX)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> emailOtpVerifier.verify(TEST_OTP, otpNamespace)).isInstanceOf(OtpExpiredException.class).hasMessage("Otp session expired.");

        verify(otpStorage).getValue(TEST_OTP_BUILT_PREFIX);
        verify(otpStorage, never()).deleteValues(anyString(), anyString(), anyString());
    }
}
