package com.vendo.auth_service.test_utils;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/test")
public class TestController {

    @GetMapping("/ping")
    public String ping() {
        return "pong";
    }

    @PostMapping("/ping")
    public PingResponse ping(@RequestBody PingRequest request) {
        return new PingResponse(request.content());
    }

}
