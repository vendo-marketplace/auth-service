package com.vendo.auth_service.domain;

public class WaitUtils {

    public static void waitSafely(long mills) {
        try {
            Thread.sleep(mills);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
