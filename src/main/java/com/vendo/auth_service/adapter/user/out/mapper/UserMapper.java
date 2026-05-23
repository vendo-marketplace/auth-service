package com.vendo.auth_service.adapter.user.out.mapper;

import com.vendo.auth_service.application.auth.dto.UserResponse;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.infrastructure.config.mapper.MapStructConfig;
import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;

@Mapper(config = MapStructConfig.class,
        componentModel = "spring",
        unmappedSourcePolicy = ReportingPolicy.IGNORE)
public interface UserMapper {

    UserResponse toResponse(User user);

}
