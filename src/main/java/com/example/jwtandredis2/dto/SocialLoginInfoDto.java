package com.example.jwtandredis2.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
//@NoArgsConstructor
@AllArgsConstructor
public class SocialLoginInfoDto {

    private String username;
    private String nickname;
}