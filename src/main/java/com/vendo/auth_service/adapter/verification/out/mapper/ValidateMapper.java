package com.vendo.auth_service.adapter.verification.out.mapper;

import com.vendo.auth_service.adapter.verification.in.dto.ValidateRequest;
import com.vendo.auth_service.application.auth.command.ValidateCommand;
import com.vendo.auth_service.infrastructure.config.mapper.MapStructConfig;
import org.mapstruct.Mapper;

@Mapper(config = MapStructConfig.class)
public interface ValidateMapper {

    ValidateCommand toCommand(ValidateRequest request);

}
