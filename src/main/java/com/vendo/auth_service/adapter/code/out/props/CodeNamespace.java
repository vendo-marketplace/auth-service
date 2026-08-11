package com.vendo.auth_service.adapter.code.out.props;

import com.vendo.redis_lib.prefix.PrefixProperties;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public abstract class CodeNamespace {

    private PrefixProperties email;

    private PrefixProperties code;

    private PrefixProperties attempts;

}
