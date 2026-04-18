package com.vendo.auth_service.adapter.user.out.mapper;

import com.vendo.auth_service.application.auth.dto.AuthUserResponse;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.infrastructure.config.mapper.MapStructConfig;
import org.mapstruct.Mapper;

@Mapper(config = MapStructConfig.class)
public interface UserMapper {

    AuthUserResponse toResponse(User user);

}
