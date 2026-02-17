package com.vendo.auth_service.adapter.otp.out.props;

import com.vendo.redis_lib.config.PrefixProperties;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public abstract class OtpNamespace {

    private PrefixProperties email;

    private PrefixProperties otp;

    private PrefixProperties attempts;

}
