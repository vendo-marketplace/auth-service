package com.vendo.auth_service.adapter.out.user;

import com.vendo.auth_service.port.user.UserInfoCommandPort;
import com.vendo.auth_service.port.user.UserInfoQueryPort;
import com.vendo.auth_service.adapter.out.user.dto.SaveUserInfoRequest;
import com.vendo.auth_service.adapter.out.user.dto.UpdateUserInfoRequest;
import com.vendo.auth_service.adapter.out.user.dto.UserInfo;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@RequiredArgsConstructor
public class UserInfoAdapter implements UserInfoQueryPort, UserInfoCommandPort {

    private final UserInfoClient userInfoClient;

    @Override
    public Optional<UserInfo> findByEmail(String email) {
        try {
            return Optional.of(userInfoClient.getByEmail(email));
        } catch (FeignException.NotFound e) {
            return Optional.empty();
        }
    }

//    @Override
//    public UserInfo ensureExists(String email) {
//        try {
//            return findByEmail(email);
//        } catch (FeignException.NotFound e) {
//
//            SaveUserInfoRequest saveUserInfoRequest = SaveUserInfoRequest.builder()
//                    .email(email)
//                    .role(UserRole.USER)
//                    .status(UserStatus.ACTIVE)
//                    .providerType(ProviderType.LOCAL)
//                    .build();
//
//            return save(saveUserInfoRequest);
//        }
//    }

    @Override
    public UserInfo save( SaveUserInfoRequest saveUserInfoRequest) {
        return userInfoClient.save(SaveUserInfoRequest.builder()
                .email(saveUserInfoRequest.email())
                .role(saveUserInfoRequest.role())
                .status(saveUserInfoRequest.status())
                .providerType(saveUserInfoRequest.providerType())
                .build());
    }

    @Override
    public void update(String id, UpdateUserInfoRequest updateUserInfoRequest) {

    }
}
