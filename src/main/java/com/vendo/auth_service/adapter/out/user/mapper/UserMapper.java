package com.vendo.auth_service.adapter.out.user.mapper;

import com.vendo.auth_service.adapter.common.config.MapStructConfig;
import com.vendo.auth_service.adapter.in.security.dto.AuthUser;
import com.vendo.auth_service.domain.user.common.dto.User;
import org.mapstruct.Mapper;

@Mapper(config = MapStructConfig.class)
public interface UserMapper {

    AuthUser toAuthUserFromUser(User user);

}
