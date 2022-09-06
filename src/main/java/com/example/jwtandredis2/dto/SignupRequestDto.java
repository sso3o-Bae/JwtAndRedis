package com.example.jwtandredis2.dto;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignupRequestDto {

    @NotBlank
    private String username;

    @NotBlank
    private String nickname;

    @NotBlank
    private String password;

    @NotBlank
    private String passwordCheck;
}