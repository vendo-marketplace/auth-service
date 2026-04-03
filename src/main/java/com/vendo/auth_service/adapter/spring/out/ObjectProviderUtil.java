package com.vendo.auth_service.adapter.spring.out;

import com.vendo.core_lib.exception.InternalServerException;
import org.springframework.beans.factory.ObjectProvider;

public final class ObjectProviderUtil {

    public static <T> T getOrThrowIfNotHttpMethodCall(ObjectProvider<T> provider) {
        T value = provider.getIfAvailable();

        if (value == null) {
            throw new InternalServerException("Couldn't inject servlet dependecies, because not a http method call.");
        }

        return value;
    }

}
