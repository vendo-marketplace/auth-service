package com.vendo.auth_service.http.user.client;

import com.vendo.auth_service.http.user.dto.SaveUserInfoRequest;
import com.vendo.auth_service.http.user.dto.UpdateUserInfoRequest;
import com.vendo.auth_service.http.user.dto.UserInfo;
import jakarta.validation.Valid;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

@Component
@FeignClient(name = "user-service")
@RequestMapping("/internal/users")
public interface UserInfoClient {

    @GetMapping
    UserInfo getByEmail(@RequestParam String email);

    @PutMapping
    void update(@RequestParam String email, @RequestBody UpdateUserInfoRequest updateUserInfoRequest);

    @PostMapping
    UserInfo save(@Valid @RequestBody SaveUserInfoRequest saveUserInfoRequest);

}
