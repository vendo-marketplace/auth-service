package com.vendo.auth_service.domain.user;

import com.vendo.auth_service.domain.user.dto.UserDataBuilder;
import com.vendo.auth_service.domain.user.exception.UserAlreadyCompletedException;
import com.vendo.auth_service.domain.user.exception.UserAlreadyVerifiedException;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.user_lib.exception.UserEmailNotVerifiedException;
import com.vendo.user_lib.type.UserRole;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.*;

class UserTest {

    @Test
    void isCompleted_shouldReturnTrue_whenFullNamePresent() {
        User user = UserDataBuilder.withAllFields().fullName("Іван Петренко").build();

        assertThat(user.isCompleted()).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    void isCompleted_shouldReturnFalse_whenFullNameNullOrEmpty(String fullName) {
        User user = UserDataBuilder.withAllFields().fullName(fullName).build();

        assertThat(user.isCompleted()).isFalse();
    }

    @Test
    void throwIfCompleted_shouldThrowUserAlreadyCompletedException_whenUserAlreadyCompleted() {
        User user = UserDataBuilder.withAllFields()
                .fullName("Іван Петренко")
                .build();

        assertThatThrownBy(user::throwIfCompleted)
                .isInstanceOf(UserAlreadyCompletedException.class)
                .hasMessage("User has already completed.");
    }

    @ParameterizedTest
    @NullAndEmptySource
    void throwIfCompleted_shouldNotThrow_whenUserNotCompleted(String fullName) {
        User user = UserDataBuilder.withAllFields().fullName(fullName).build();

        assertThatNoException().isThrownBy(user::throwIfCompleted);
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

    @Test
    void throwIfVerified_shouldThrowUserAlreadyVerifiedException_whenEmailVerified() {
        User user = UserDataBuilder.withAllFields().emailVerified(true).build();

        assertThatThrownBy(user::throwIfVerified)
                .isInstanceOf(UserAlreadyVerifiedException.class)
                .hasMessage("User email is already verified.");
    }

    @Test
    void throwIfVerified_shouldNotThrow_whenEmailNotVerified() {
        User user = UserDataBuilder.withAllFields().emailVerified(false).build();

        assertThatNoException().isThrownBy(user::throwIfVerified);
    }

    @ParameterizedTest
    @ValueSource(strings = {"Іван Петренко", "Їжак Ґудзь", "Єва Щербань", "Мар'яна Солов'як", "Юрій Ільюк"})
    void isValidFullName_shouldReturnTrue_whenTwoCapitalizedUkrainianWords(String fullName) {
        assertThat(User.isValidFullName(fullName)).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            "John Doe", "Іван Doe", "John Петренко", "Iван Петренко",
            "Эдуард Петренко", "Ёжик Петренко", "Іван Бызов", "Іван Подъячев", "Ьван Петренко",
            "Іван", "іван петренко", "Іван петренко", "ІВАН ПЕТРЕНКО", "Іван Петрович Петренко",
            "Іван  Петренко", " Іван Петренко", "Іван Петренко ", "Анна-Марія Петренко", "Іван П", "Іван1 Петренко"
    })
    void isValidFullName_shouldReturnFalse_whenNameDoesNotMatchPattern(String fullName) {
        assertThat(User.isValidFullName(fullName)).isFalse();
    }

    @ParameterizedTest
    @CsvSource({
                        "Іван Петренко, Іван П."
    })
    void normalizeFullName_shouldReturnFirstNameAndLastNameInitial(String fullName, String expected) {
        assertThat(User.normalizeFullName(fullName)).isEqualTo(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {"Іван", "Іван Петрович Петренко", "Іван  Петренко"})
    void normalizeFullName_shouldThrowIllegalArgumentException_whenNotTwoWords(String fullName) {
        assertThatThrownBy(() -> User.normalizeFullName(fullName))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Full name doesn't contain first name and last name.");
    }

    @Test
    void toRoleNames_shouldReturnRoleNames() {
        Set<UserRole> roles = EnumSet.allOf(UserRole.class);
        User user = UserDataBuilder.withAllFields().roles(roles).build();

        Set<String> expected = roles.stream().map(Enum::name).collect(Collectors.toSet());

        assertThat(user.toRoleNames()).isEqualTo(expected);
    }

    @Test
    void toRoleNames_shouldReturnEmptySet_whenNoRoles() {
        User user = UserDataBuilder.withAllFields().roles(Set.of()).build();

        assertThat(user.toRoleNames()).isEmpty();
    }
}
