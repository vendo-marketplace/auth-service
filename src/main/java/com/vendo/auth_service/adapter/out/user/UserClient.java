package com.vendo.auth_service.adapter.out.user;

import com.vendo.auth_service.domain.user.common.dto.SaveUserRequest;
import com.vendo.auth_service.domain.user.common.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.common.dto.User;
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
    boolean existsByEmail(@RequestParam String email);

    @PutMapping
    void update(@RequestParam String id, @RequestBody UpdateUserRequest updateUserRequest);

    @PostMapping
    User save(@Valid @RequestBody SaveUserRequest saveUserRequest);
}
