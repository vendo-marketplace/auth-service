package com.vendo.auth_service.application.code;

import com.vendo.auth_service.adapter.code.out.props.CodeNamespace;
import com.vendo.auth_service.port.code.CodeStorage;
import com.vendo.redis_lib.exception.CodeExpiredException;
import com.vendo.redis_lib.prefix.PrefixProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class EmailCodeServiceTest {

    private static final String TEST_EMAIL = "email@gmail.com";
    private static final String TEST_CODE = "code";
    private static final String TEST_CODE_BUILT_PREFIX = "code:" + TEST_CODE;
    private static final String TEST_EMAIL_BUILT_PREFIX = "email:" + TEST_EMAIL;
    private static final String TEST_ATTEMPTS_BUILT_PREFIX = "attempts:" + TEST_EMAIL;

    @InjectMocks
    private EmailCodeService emailCodeVerifier;

    @Mock
    private CodeStorage codeStorage;
    @Mock
    private CodeNamespace codeNamespace;
    @Mock
    private PrefixProperties emailPrefix;
    @Mock
    private PrefixProperties codePrefix;
    @Mock
    private PrefixProperties attemptsPrefix;

    @Test
    void verify_shouldReturnEmail_whenCodeValid() {
        when(codeNamespace.getCode()).thenReturn(codePrefix);
        when(codeNamespace.getEmail()).thenReturn(emailPrefix);
        when(codeNamespace.getAttempts()).thenReturn(attemptsPrefix);
        when(codePrefix.buildPrefix(TEST_CODE)).thenReturn(TEST_CODE_BUILT_PREFIX);
        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_EMAIL_BUILT_PREFIX);
        when(attemptsPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_ATTEMPTS_BUILT_PREFIX);

        when(codeStorage.getValue(TEST_CODE_BUILT_PREFIX)).thenReturn(Optional.of(TEST_EMAIL));

        emailCodeVerifier.consume(TEST_CODE, codeNamespace);

        verify(codeStorage).getValue(TEST_CODE_BUILT_PREFIX);
        verify(codeStorage).deleteValues(
                TEST_CODE_BUILT_PREFIX,
                TEST_EMAIL_BUILT_PREFIX,
                TEST_ATTEMPTS_BUILT_PREFIX
        );
    }

    @Test
    void verify_shouldThrowCodeExpiredException_whenCodeExpired() {
        when(codeNamespace.getCode()).thenReturn(codePrefix);
        when(codePrefix.buildPrefix(TEST_CODE)).thenReturn(TEST_CODE_BUILT_PREFIX);
        when(codeStorage.getValue(TEST_CODE_BUILT_PREFIX)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> emailCodeVerifier.consume(TEST_CODE, codeNamespace)).isInstanceOf(CodeExpiredException.class).hasMessage("Code session expired.");

        verify(codeStorage).getValue(TEST_CODE_BUILT_PREFIX);
        verify(codeStorage, never()).deleteValues(anyString(), anyString(), anyString());
    }
}
