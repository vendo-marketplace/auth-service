package com.vendo.auth_service.domain.user;

import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.model.User;
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
        User user = UserDataBuilder.withAllFields().status(UserStatus.INCOMPLETE).build();

        assertThatCode(user::validateCompletion).doesNotThrowAnyException();
    }

    @Test
    void validateCompletion_shouldThrowUserBlockedException_whenUserBlocked() {
        User user = UserDataBuilder.withAllFields().status(UserStatus.BLOCKED).build();

        assertThatThrownBy(user::validateCompletion).isInstanceOf(UserBlockedException.class).hasMessage("User is blocked.");
    }

    @Test
    void validateActivity_shouldSuccessfullyValidate_whenUserIsValid() {
        User user = UserDataBuilder.withAllFields().status(UserStatus.ACTIVE).build();

        assertThatCode(user::validateActivity).doesNotThrowAnyException();
    }

    @Test
    void validateActivity_shouldThrowIllegalArgumentException_whenStatusNull() {
        User user = UserDataBuilder.withAllFields().status(null).build();

        assertThatThrownBy(user::validateActivity).isInstanceOf(IllegalArgumentException.class).hasMessage("Status and email verification are required.");
    }

    @Test
    void validateActivity_shouldThrowIllegalArgumentException_whenEmailNull() {
        User user = UserDataBuilder.withAllFields().emailVerified(null).build();

        assertThatThrownBy(user::validateActivity).isInstanceOf(IllegalArgumentException.class).hasMessage("Status and email verification are required.");
    }

    @Test
    void validateActivity_shouldThrowUserBlockedException_whenUserBlocked() {
        User user = UserDataBuilder.withAllFields().status(UserStatus.BLOCKED).build();

        assertThatThrownBy(user::validateActivity).isInstanceOf(UserBlockedException.class).hasMessage("User is blocked.");
    }

    @Test
    void validateActivity_shouldThrowUserIsUnactiveException_whenUserUnactive() {
        User user = UserDataBuilder.withAllFields().status(UserStatus.INCOMPLETE).build();

        assertThatThrownBy(user::validateActivity).isInstanceOf(UserIsUnactiveException.class).hasMessage("User is unactive.");
    }

    @Test
    void validateActivity_shouldThrowUserEmailNotVerifiedException_whenEmailNotVerified() {
        User user = UserDataBuilder.withAllFields().status(UserStatus.ACTIVE).emailVerified(false).build();

        assertThatThrownBy(user::validateActivity).isInstanceOf(UserEmailNotVerifiedException.class).hasMessage("User email is not verified.");
    }

}
