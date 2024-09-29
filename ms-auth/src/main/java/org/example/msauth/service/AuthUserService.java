package org.example.msauth.service;

import org.example.msauth.dto.AuthUserDto;
import org.example.msauth.entity.AuthUser;
import org.example.msauth.entity.TokenDto;


public interface AuthUserService {
    public AuthUser save(AuthUserDto authUserDto);


    public TokenDto login(AuthUserDto authUserDto);


    public TokenDto validate(String token);
}