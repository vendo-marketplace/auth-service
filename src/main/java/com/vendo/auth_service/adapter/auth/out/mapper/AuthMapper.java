package com.vendo.auth_service.adapter.auth.out.mapper;

import com.vendo.auth_service.adapter.auth.in.dto.AuthRequest;
import com.vendo.auth_service.adapter.auth.in.dto.CompleteAuthRequest;
import com.vendo.auth_service.adapter.auth.in.dto.RefreshRequest;
import com.vendo.auth_service.application.auth.command.AuthCommand;
import com.vendo.auth_service.application.auth.command.CompleteAuthCommand;
import com.vendo.auth_service.application.auth.command.RefreshCommand;
import com.vendo.auth_service.bootstrap.config.mapper.MapStructConfig;
import org.mapstruct.Mapper;

@Mapper(config = MapStructConfig.class)
public interface AuthMapper {

    AuthCommand toCommand(AuthRequest request);

    CompleteAuthCommand toCompleteCommand(CompleteAuthRequest request);

    RefreshCommand toRefreshCommand(RefreshRequest request);

}
