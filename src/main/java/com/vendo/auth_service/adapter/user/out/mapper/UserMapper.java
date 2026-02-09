package com.vendo.auth_service.adapter.user.out.mapper;

import com.vendo.auth_service.bootstrap.config.mapper.MapStructConfig;
import com.vendo.auth_service.domain.security.dto.AuthUser;
import com.vendo.auth_service.domain.user.model.User;
import org.mapstruct.Mapper;

@Mapper(config = MapStructConfig.class)
public interface UserMapper {

    AuthUser toAuthUserFromUser(User user);

}
