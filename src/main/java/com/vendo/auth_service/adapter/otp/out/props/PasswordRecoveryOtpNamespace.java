package com.vendo.auth_service.adapter.otp.out.props;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "redis.password-recovery")
public class PasswordRecoveryOtpNamespace extends OtpNamespace {
}
