package com.vendo.auth_service.adapter.db.redis.out;

import com.vendo.auth_service.port.code.CodeStorage;
import com.vendo.auth_service.port.code.StorageValue;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
class RedisCodeStorage implements CodeStorage {

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
    public void saveValues(Map<String, StorageValue> values) {
        redisService.saveValues(values);
    }

    @Override
    public void deleteValues(String... keys) {
        redisService.deleteValues(keys);
    }

}
