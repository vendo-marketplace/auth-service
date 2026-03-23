package com.vendo.auth_service.adapter.user.out;

import com.vendo.auth_service.adapter.user.in.dto.UserExistsResponse;
import com.vendo.auth_service.adapter.user.out.config.UserFeignConfig;
import com.vendo.auth_service.application.auth.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.model.User;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

@Component
@FeignClient(
        name = "user-service",
        path = "/internal/users",
        configuration = UserFeignConfig.class)
public interface UserClient {

    @GetMapping
    User getByEmail(@RequestParam("email") String email);

    @GetMapping("/exists")
    UserExistsResponse existsByEmail(@RequestParam("email") String email);

    @PutMapping
    void update(@RequestParam("id") String id, @RequestBody UpdateUserRequest body);

    @PostMapping
    User save(@RequestBody User body);

}
