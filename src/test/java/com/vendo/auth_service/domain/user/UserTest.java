package com.vendo.auth_service.domain.user;

import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.user_lib.exception.UserAlreadyCompletedException;
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
}
