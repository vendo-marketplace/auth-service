package com.vendo.auth_service.domain.user;

import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.user_lib.exception.UserAlreadyCompletedException;
import com.vendo.user_lib.exception.UserEmailNotVerifiedException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDate;

import static org.assertj.core.api.AssertionsForClassTypes.*;

@ExtendWith(MockitoExtension.class)
public class UserTest {

    @Test
    void validateComplete_shouldThrowUserAlreadyCompletedException_whenUserAlreadyCompleted() {
        User user = UserDataBuilder.withAllFields()
                .fullName("John Doe")
                .birthDate(LocalDate.of(1991, 12, 12))
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
}
