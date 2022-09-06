package com.example.jwtandredis2.dto;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequestDto {

    @NotBlank
    private String username;

    @NotBlank
    private String password;
}