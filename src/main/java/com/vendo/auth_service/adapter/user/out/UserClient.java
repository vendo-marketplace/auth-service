package com.vendo.auth_service.adapter.user.out;

import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.adapter.user.in.dto.UserExistsResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

@Component
@FeignClient(name = "user-service", path = "/internal/users")
public interface UserClient {

    @GetMapping
    User getByEmail(@RequestParam("email") String email);

    @GetMapping("/exists")
    UserExistsResponse existsByEmail(@RequestParam("email") String email);

    @PutMapping
    void update(@RequestParam("id") String id, @RequestBody User body);

    @PostMapping
    User save(@RequestBody User body);
}
