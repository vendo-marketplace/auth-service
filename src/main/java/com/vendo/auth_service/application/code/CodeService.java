package com.vendo.auth_service.application.code;

import com.vendo.auth_service.adapter.code.out.props.CodeNamespace;

public interface CodeService {

    String consume(String code, CodeNamespace namespace);

    String peek(String code, CodeNamespace namespace);

    void cleanUp(String code, CodeNamespace namespace);

}