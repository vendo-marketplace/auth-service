package com.vendo.auth_service.application.code;

import com.vendo.auth_service.adapter.code.out.props.CodeNamespace;
import com.vendo.auth_service.application.auth.command.CodeCommand;
import com.vendo.auth_service.domain.code.exception.CodeAlreadySentException;
import com.vendo.auth_service.domain.code.exception.TooManyCodeRequestsException;
import com.vendo.auth_service.port.code.StorageValue;
import com.vendo.auth_service.port.code.CodeEmailNotificationPort;
import com.vendo.auth_service.port.code.CodeGenerator;
import com.vendo.auth_service.port.code.CodeStorage;
import com.vendo.event_lib.code.CodeEventType;
import com.vendo.redis_lib.exception.CodeExpiredException;
import com.vendo.redis_lib.prefix.PrefixProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class EmailCodeSenderTest {

    @InjectMocks
    private EmailCodeSender codeSender;

    @Mock
    private CodeGenerator codeGenerator;
    @Mock
    private CodeStorage codeStorage;
    @Mock
    private CodeEmailNotificationPort codeEmailNotificationPort;
    @Mock
    private CodeNamespace codeNamespace;

    @Mock
    private PrefixProperties emailPrefix;
    @Mock
    private PrefixProperties codePrefix;
    @Mock
    private PrefixProperties attemptsPrefix;

    private static final String TEST_EMAIL = "email@gmail.com";
    private static final String TEST_OLD_CODE = "old-code";
    private static final String TEST_CODE = "code";
    private static final long TEST_TTL = 300L;

    private static final String TEST_CODE_BUILT_PREFIX = "code:" + TEST_CODE;
    private static final String TEST_EMAIL_BUILT_PREFIX = "email:" + TEST_EMAIL;
    private static final String TEST_ATTEMPTS_BUILT_PREFIX = "attempts:" + TEST_EMAIL;

    @Test
    void send_shouldSuccessfullySendCode_whenCodeNotSentYet() {
        CodeCommand codeCommand = new CodeCommand(TEST_EMAIL, CodeEventType.EMAIL_VERIFICATION);
        Map<String, StorageValue> values = Map.of(
                TEST_CODE_BUILT_PREFIX, new StorageValue(TEST_EMAIL, TEST_TTL),
                TEST_EMAIL_BUILT_PREFIX, new StorageValue(TEST_CODE, TEST_TTL)
        );

        when(codeNamespace.getEmail()).thenReturn(emailPrefix);
        when(codeNamespace.getCode()).thenReturn(codePrefix);

        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_EMAIL_BUILT_PREFIX);
        when(emailPrefix.ttl()).thenReturn(TEST_TTL);

        when(codePrefix.buildPrefix(TEST_CODE)).thenReturn(TEST_CODE_BUILT_PREFIX);
        when(codePrefix.ttl()).thenReturn(TEST_TTL);

        when(codeStorage.hasActiveKey(TEST_EMAIL_BUILT_PREFIX)).thenReturn(false);
        when(codeGenerator.generate()).thenReturn(TEST_CODE);

        codeSender.send(codeCommand, codeNamespace);

        verify(codeStorage).hasActiveKey(TEST_EMAIL_BUILT_PREFIX);
        verify(codeGenerator).generate();
        verify(codeStorage).saveValues(values);
        verify(codeEmailNotificationPort).sendEmailNotification(
                argThat(event ->
                        event.email().equals(TEST_EMAIL) &&
                                event.type() == CodeEventType.EMAIL_VERIFICATION &&
                                event.code().equals(TEST_CODE)
                )
        );
    }

    @Test
    void send_shouldThrowCodeAlreadySentException_whenCodeAlreadySent() {
        CodeCommand codeCommand = new CodeCommand(TEST_EMAIL, CodeEventType.EMAIL_VERIFICATION);

        when(codeNamespace.getEmail()).thenReturn(emailPrefix);

        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_EMAIL_BUILT_PREFIX);

        when(codeStorage.hasActiveKey(TEST_EMAIL_BUILT_PREFIX)).thenReturn(true);

        assertThatThrownBy(() -> codeSender.send(codeCommand, codeNamespace)).isInstanceOf(CodeAlreadySentException.class).hasMessage("Code already sent.");

        verify(codeStorage).hasActiveKey(TEST_EMAIL_BUILT_PREFIX);
        verifyNoInteractions(codeGenerator, codeEmailNotificationPort);

        verify(codeStorage, never()).saveValue(anyString(), anyString(), anyLong());
    }

    @Test
    void resend_shouldSuccessfullyResendCode_whenOldCodeValidAndNoAttempts() {
        CodeCommand codeCommand = new CodeCommand(TEST_EMAIL, CodeEventType.EMAIL_VERIFICATION);

        when(codeNamespace.getEmail()).thenReturn(emailPrefix);
        when(codeNamespace.getAttempts()).thenReturn(attemptsPrefix);

        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_EMAIL_BUILT_PREFIX);
        when(attemptsPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_ATTEMPTS_BUILT_PREFIX);
        when(attemptsPrefix.ttl()).thenReturn(TEST_TTL);

        when(codeStorage.getValue(TEST_EMAIL_BUILT_PREFIX)).thenReturn(Optional.of(TEST_OLD_CODE));
        when(codeStorage.getValue(TEST_ATTEMPTS_BUILT_PREFIX)).thenReturn(Optional.empty());

        codeSender.resend(codeCommand, codeNamespace);

        verify(codeStorage).getValue(TEST_EMAIL_BUILT_PREFIX);
        verify(codeGenerator, never()).generate();
        verify(codeStorage, never()).saveValue(eq(TEST_EMAIL_BUILT_PREFIX), anyString(), anyLong());
        verify(codeStorage).getValue(TEST_ATTEMPTS_BUILT_PREFIX);
        verify(codeStorage).saveValue(TEST_ATTEMPTS_BUILT_PREFIX, "1", TEST_TTL);
        verify(codeEmailNotificationPort).sendEmailNotification(
                argThat(event ->
                        event.email().equals(TEST_EMAIL) &&
                                event.type() == CodeEventType.EMAIL_VERIFICATION &&
                                event.code().equals(TEST_OLD_CODE)
                )
        );
    }

    @Test
    void resend_shouldThrowCodeExpiredException_whenNoActiveCodeSession() {
        CodeCommand codeCommand = new CodeCommand(TEST_EMAIL, CodeEventType.EMAIL_VERIFICATION);

        when(codeNamespace.getEmail()).thenReturn(emailPrefix);
        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_EMAIL_BUILT_PREFIX);
        when(codeStorage.getValue(TEST_EMAIL_BUILT_PREFIX)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> codeSender.resend(codeCommand, codeNamespace))
                .isInstanceOf(CodeExpiredException.class)
                .hasMessage("No active code session found.");

        verify(codeStorage).getValue(TEST_EMAIL_BUILT_PREFIX);
        verifyNoInteractions(codeGenerator, codeEmailNotificationPort);
        verify(codeStorage, never()).saveValue(anyString(), anyString(), anyLong());
    }

    @Test
    void resend_shouldThrowTooManyCodeRequestsException_whenCodeValidAndExceededAttempts() {
        CodeCommand codeCommand = new CodeCommand(TEST_EMAIL, CodeEventType.EMAIL_VERIFICATION);

        when(codeNamespace.getEmail()).thenReturn(emailPrefix);
        when(codeNamespace.getAttempts()).thenReturn(attemptsPrefix);
        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_EMAIL_BUILT_PREFIX);
        when(attemptsPrefix.buildPrefix(TEST_EMAIL)).thenReturn(TEST_ATTEMPTS_BUILT_PREFIX);

        when(codeStorage.getValue(TEST_EMAIL_BUILT_PREFIX)).thenReturn(Optional.of(TEST_CODE));
        when(codeStorage.getValue(TEST_ATTEMPTS_BUILT_PREFIX)).thenReturn(Optional.of("3"));

        assertThatThrownBy(() -> codeSender.resend(codeCommand, codeNamespace)).isInstanceOf(TooManyCodeRequestsException.class).hasMessage("Reached maximum attempts.");

        verify(codeStorage).getValue(TEST_EMAIL_BUILT_PREFIX);
        verify(codeStorage).getValue(TEST_ATTEMPTS_BUILT_PREFIX);
        verify(codeStorage, never()).saveValue(eq(TEST_ATTEMPTS_BUILT_PREFIX), anyString(), anyLong());

        verifyNoInteractions(codeEmailNotificationPort);
        verifyNoMoreInteractions(codeStorage);
    }

}
