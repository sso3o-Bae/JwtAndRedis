package com.example.jwtandredis2.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginIdCheckDto {
    private String username;
    private String nickname;

}