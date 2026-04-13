package com.vendo.auth_service.test_utils;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@PreAuthorize("@userSecurity.validateAuthCompletedAdmin(authentication)")
@RequestMapping("/test")
public class AdminTestController {

    @GetMapping("/admin/ping")
    public String ping() {
        return "pong";
    }

}
