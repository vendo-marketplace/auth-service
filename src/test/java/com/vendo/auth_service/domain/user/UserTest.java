package com.vendo.auth_service.domain.user;

import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.exception.UserAlreadyCompletedException;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.user_lib.exception.UserBlockedException;
import com.vendo.user_lib.type.UserStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDate;

import static org.assertj.core.api.AssertionsForClassTypes.*;

@ExtendWith(MockitoExtension.class)
public class UserTest {

    @Test
    void validateCompletion_shouldThrowUserBlockedException_whenUserBlocked() {
        User user = UserDataBuilder.withAllFields().status(UserStatus.BLOCKED).build();

        assertThatThrownBy(user::validateCompletion)
                .isInstanceOf(UserBlockedException.class)
                .hasMessage("User is blocked.");
    }

    @Test
    void validateCompletion_shouldThrowIllegalStateException_whenUserAlreadyCompleted() {
        User user = UserDataBuilder.withAllFields()
                .fullName("John Doe")
                .birthDate(LocalDate.of(1991, 12, 12))
                .build();

        assertThatThrownBy(user::validateCompletion)
                .isInstanceOf(UserAlreadyCompletedException.class)
                .hasMessage("User profile is already completed.");

    }
}
