package com.vendo.auth_service.adapter.out.db.redis.common.namespace.otp;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "redis.email-verification")
public class EmailVerificationOtpNamespace extends OtpNamespace {

}
