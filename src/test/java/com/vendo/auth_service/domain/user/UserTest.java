package com.vendo.auth_service.domain.user;

import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.user_lib.exception.UserAlreadyCompletedException;
import com.vendo.user_lib.exception.UserBlockedException;
import com.vendo.user_lib.exception.UserEmailNotVerifiedException;
import com.vendo.user_lib.type.UserStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDate;

import static org.assertj.core.api.AssertionsForClassTypes.*;

@ExtendWith(MockitoExtension.class)
public class UserTest {

    @Test
    void validateAccess_shouldThrowUserBlockedException_whenUserBlocked() {
        User user = UserDataBuilder.withAllFields().status(UserStatus.BLOCKED).build();

        assertThatThrownBy(user::validateAccess)
                .isInstanceOf(UserBlockedException.class)
                .hasMessage("User is blocked.");
    }

    @Test
    void throwIfNotVerified_shouldThrowUserEmailNotVerifiedException_whenUserNotVerified() {
        User user = UserDataBuilder.withAllFields().emailVerified(false).build();

        assertThatThrownBy(user::validateAccess)
                .isInstanceOf(UserEmailNotVerifiedException.class)
                .hasMessage("User email is not verified.");
    }

    @Test
    void throwIfBlocked_UserBlockedException_whenUserBlocked() {
        User user = UserDataBuilder.withAllFields().status(UserStatus.BLOCKED).build();

        assertThatThrownBy(user::validateAccess)
                .isInstanceOf(UserBlockedException.class)
                .hasMessage("User is blocked.");
    }

    @Test
    void throwIfCompleted_shouldThrowUserAlreadyCompletedException_whenUserAlreadyCompleted() {
        User user = UserDataBuilder.withAllFields()
                .fullName("John Doe")
                .birthDate(LocalDate.of(1991, 12, 12))
                .build();

        assertThatThrownBy(user::throwIfCompleted)
                .isInstanceOf(UserAlreadyCompletedException.class)
                .hasMessage("User is already completed.");

    }
}
