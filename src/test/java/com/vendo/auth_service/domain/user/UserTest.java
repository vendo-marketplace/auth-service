package com.vendo.auth_service.domain.user;

import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.exception.UserAlreadyCompletedException;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.user_lib.exception.UserEmailNotVerifiedException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.AssertionsForClassTypes.*;

@ExtendWith(MockitoExtension.class)
public class UserTest {

    @Test
    void validateComplete_shouldThrowUserAlreadyCompletedException_whenUserAlreadyCompleted() {
        User user = UserDataBuilder.withAllFields()
                .fullName("John Doe")
                .build();

        assertThatThrownBy(user::throwIfCompleted)
                .isInstanceOf(UserAlreadyCompletedException.class)
                .hasMessage("User has already completed.");
    }

    @Test
    void throwIfEmailNotVerified_shouldThrowUserEmailNotVerifiedException_whenEmailNotVerified() {
        User user = UserDataBuilder.withAllFields().emailVerified(false).build();

        assertThatThrownBy(user::throwIfEmailNotVerified)
                .isInstanceOf(UserEmailNotVerifiedException.class)
                .hasMessage("User email is not verified.");
    }

    @Test
    void throwIfEmailNotVerified_shouldNotThrow_whenEmailVerified() {
        User user = UserDataBuilder.withAllFields().emailVerified(true).build();

        assertThatNoException().isThrownBy(user::throwIfEmailNotVerified);
    }

    @ParameterizedTest
    @ValueSource(strings = {"John Doe", "Іван Петренко"})
    void isValidFullName_shouldReturnTrue_whenTwoCapitalizedWords(String fullName) {
        assertThat(User.isValidFullName(fullName)).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"John", "john doe", "John Ronald Doe", "José Doe"})
    void isValidFullName_shouldReturnFalse_whenNameDoesNotMatchPattern(String fullName) {
        assertThat(User.isValidFullName(fullName)).isFalse();
    }
}
