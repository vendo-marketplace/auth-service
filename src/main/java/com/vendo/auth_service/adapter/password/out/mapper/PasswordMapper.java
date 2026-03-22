package com.vendo.auth_service.adapter.password.out.mapper;

import com.vendo.auth_service.adapter.password.in.dto.ResetPasswordRequest;
import com.vendo.auth_service.application.password.command.ResetPasswordCommand;
import com.vendo.auth_service.infrastructure.config.mapper.MapStructConfig;
import org.mapstruct.Mapper;

@Mapper(config = MapStructConfig.class)
public interface PasswordMapper {

    ResetPasswordCommand toCommand(ResetPasswordRequest request);

}
