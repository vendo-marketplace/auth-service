package com.vendo.auth_service.port.code;

import java.util.Map;
import java.util.Optional;

public interface CodeStorage {

    Optional<String> getValue(String key);

    boolean hasActiveKey(String key);

    void saveValue(String key, String value, long ttl);

    void saveValues(Map<String, StorageValue> values);

    void deleteValues(String... keys);

}
