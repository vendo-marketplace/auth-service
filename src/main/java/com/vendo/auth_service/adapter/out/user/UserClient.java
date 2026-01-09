package com.vendo.auth_service.adapter.out.user;

import com.vendo.auth_service.adapter.out.user.dto.SaveUserRequest;
import com.vendo.auth_service.adapter.out.user.dto.UpdateUserRequest;
import com.vendo.auth_service.adapter.out.user.dto.User;
import jakarta.validation.Valid;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

@Component
@FeignClient(name = "user-service")
@RequestMapping("/internal/users")
public interface UserClient {

    @GetMapping
    User getById(@RequestParam String id);

    @GetMapping
    User getByEmail(@RequestParam String email);

    @PutMapping
    void update(@RequestParam String email, @RequestBody UpdateUserRequest updateUserRequest);

    @PostMapping
    User save(@Valid @RequestBody SaveUserRequest saveUserRequest);

}
