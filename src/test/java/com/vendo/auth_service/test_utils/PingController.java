package com.vendo.auth_service.test_utils;

import com.vendo.auth_service.test_utils.dto.PingRequest;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/test")
public class PingController {

    @GetMapping("/ping")
    public String ping() {
        return "pong";
    }

    @PostMapping("/ping")
    public String ping(@RequestBody PingRequest request) {
        return request.content();
    }

}
