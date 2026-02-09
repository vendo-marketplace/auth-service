package com.vendo.auth_service.adapter.user.out;

import com.vendo.auth_service.domain.user.dto.SaveUserRequest;
import com.vendo.auth_service.domain.user.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.domain.user.dto.UserExistsResponse;
import jakarta.validation.Valid;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

@Component
@FeignClient(name = "user-service")
@RequestMapping("/internal/users")
public interface UserClient {

    @GetMapping
    User getByEmail(@RequestParam String email);

    @GetMapping("/exists")
    UserExistsResponse existsByEmail(@RequestParam String email);

    @PutMapping
    void update(@RequestParam String id, @RequestBody UpdateUserRequest updateUserRequest);

    @PostMapping
    User save(@Valid @RequestBody SaveUserRequest saveUserRequest);
}
