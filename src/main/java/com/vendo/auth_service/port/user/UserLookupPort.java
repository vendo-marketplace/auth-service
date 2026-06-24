package com.vendo.auth_service.port.user;

public interface UserLookupPort {

    void requireExistence(String email);

}
