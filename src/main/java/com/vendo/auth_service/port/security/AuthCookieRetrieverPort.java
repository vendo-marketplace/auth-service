package com.vendo.auth_service.port.security;

public interface AuthCookieRetrieverPort {

    String retrieveAccess();
    String retrieveRefresh();

}
