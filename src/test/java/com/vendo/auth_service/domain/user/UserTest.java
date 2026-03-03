package com.vendo.auth_service.domain.user;

import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.user_lib.exception.UserAlreadyActivatedException;
import com.vendo.user_lib.exception.UserBlockedException;
import com.vendo.user_lib.type.UserStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.AssertionsForClassTypes.*;

@ExtendWith(MockitoExtension.class)
public class UserTest {
    @Test
    void validateBeforeActivation_shouldSuccessfullyValidate_whenUserIsValid() {
        User user = UserDataBuilder.buildUserAllFields().status(UserStatus.INCOMPLETE).build();

        assertThatCode(user::validateBeforeActivation).doesNotThrowAnyException();
    }

    @Test
    void validateBeforeActivation_shouldThrowUserBlockedException_whenUserBlocked() {
        User user = UserDataBuilder.buildUserAllFields().status(UserStatus.BLOCKED).build();

        assertThatThrownBy(user::validateBeforeActivation).isInstanceOf(UserBlockedException.class).hasMessage("User is blocked.");
    }

    @Test
     void validateBeforeActivation_shouldThrowUserAlreadyActivatedException_whenUserActive() {
        User user = UserDataBuilder.buildUserAllFields().status(UserStatus.ACTIVE).build();

        assertThatThrownBy(user::validateBeforeActivation).isInstanceOf(UserAlreadyActivatedException.class).hasMessage("User account is already active.");
    }
}
