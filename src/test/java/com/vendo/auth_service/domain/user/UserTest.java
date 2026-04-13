package com.vendo.auth_service.domain.user;

import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.user_lib.exception.UserAlreadyActivatedException;
import com.vendo.user_lib.exception.UserBlockedException;
import com.vendo.user_lib.exception.UserEmailNotVerifiedException;
import com.vendo.user_lib.exception.UserIsUnactiveException;
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

    @Test
    void validateActivity_shouldSuccessfullyValidate_whenUserIsValid() {
        User user = UserDataBuilder.buildUserAllFields().status(UserStatus.ACTIVE).build();

        assertThatCode(user::validateActivity).doesNotThrowAnyException();
    }

    @Test
    void validateActivity_shouldThrowIllegalArgumentException_whenStatusNull() {
        User user = UserDataBuilder.buildUserAllFields().status(null).build();

        assertThatThrownBy(user::validateActivity).isInstanceOf(IllegalArgumentException.class).hasMessage("Status and email verification are required.");
    }

    @Test
    void validateActivity_shouldThrowIllegalArgumentException_whenEmailNull() {
        User user = UserDataBuilder.buildUserAllFields().emailVerified(null).build();

        assertThatThrownBy(user::validateActivity).isInstanceOf(IllegalArgumentException.class).hasMessage("Status and email verification are required.");
    }

    @Test
    void validateActivity_shouldThrowUserBlockedException_whenUserBlocked() {
        User user = UserDataBuilder.buildUserAllFields().status(UserStatus.BLOCKED).build();

        assertThatThrownBy(user::validateActivity).isInstanceOf(UserBlockedException.class).hasMessage("User is blocked.");
    }

    @Test
    void validateActivity_shouldThrowUserIsUnactiveException_whenUserUnactive() {
        User user = UserDataBuilder.buildUserAllFields().status(UserStatus.INCOMPLETE).build();

        assertThatThrownBy(user::validateActivity).isInstanceOf(UserIsUnactiveException.class).hasMessage("User is unactive.");
    }

    @Test
    void validateActivity_shouldThrowUserEmailNotVerifiedException_whenEmailNotVerified() {
        User user = UserDataBuilder.buildUserAllFields().status(UserStatus.ACTIVE).emailVerified(false).build();

        assertThatThrownBy(user::validateActivity).isInstanceOf(UserEmailNotVerifiedException.class).hasMessage("User email is not verified.");
    }

}
