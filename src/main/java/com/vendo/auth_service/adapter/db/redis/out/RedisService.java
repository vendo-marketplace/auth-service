package com.vendo.auth_service.adapter.db.redis.out;

import com.vendo.auth_service.port.otp.StorageValue;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RedisService {

    private final RedisTemplate<String, String> redisTemplate;

    public void saveValue(String key, String value, long seconds) {
        redisTemplate.opsForValue().set(key, value, Duration.ofSeconds(seconds));
    }

    public void saveValues(Map<String, StorageValue> values) {
        redisTemplate.execute(new SessionCallback<>() {

            @Override
            @SuppressWarnings("unchecked")
            public Object execute(@NonNull RedisOperations ops) {
                ops.multi();
                values.forEach((key, storageValue) -> ops.opsForValue().set(
                        key,
                        storageValue.payload(),
                        storageValue.ttl(),
                        TimeUnit.SECONDS)
                );
                return ops.exec();
            }
        });
    }

    public Optional<String> getValue(String key) {
        return Optional.ofNullable(redisTemplate.opsForValue().get(key));
    }

    public void deleteValues(String... keys) {
        redisTemplate.delete(List.of(keys));
    }

    public boolean hasActiveKey(String key) {
        return redisTemplate.hasKey(key);
    }

}
