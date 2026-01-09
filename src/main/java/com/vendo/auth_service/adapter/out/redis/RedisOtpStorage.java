package com.vendo.auth_service.adapter.out.redis;

import com.vendo.auth_service.port.otp.OtpStorage;
import com.vendo.auth_service.system.redis.service.RedisService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RedisOtpStorage implements OtpStorage {

    private final RedisService redisService;

    @Override
    public Optional<String> getValue(String key) {
        return redisService.getValue(key);
    }

    @Override
    public boolean hasActiveKey(String key) {
        return redisService.hasActiveKey(key);
    }

    @Override
    public void saveValue(String key, String value, long ttl) {
        redisService.saveValue(key, value, ttl);
    }

    @Override
    public void deleteValues(String... keys) {
        redisService.deleteValues(keys);
    }

}
