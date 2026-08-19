package com.vendo.auth_service.port.auth;

public interface GoogleAuthCodePort {

    String exchange(String authCode);

}
