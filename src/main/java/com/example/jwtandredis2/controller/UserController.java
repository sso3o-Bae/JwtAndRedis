package com.example.jwtandredis2.controller;


import com.example.jwtandredis2.auth.UserDetailsImpl;
import com.example.jwtandredis2.dto.LoginIdCheckDto;
import com.example.jwtandredis2.dto.SignupRequestDto;
import com.example.jwtandredis2.jwtwithRedis.Helper;
import com.example.jwtandredis2.jwtwithRedis.JwtTokenProvider;
import com.example.jwtandredis2.jwtwithRedis.Response;
import com.example.jwtandredis2.jwtwithRedis.UserRequestDto;
import com.example.jwtandredis2.service.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.Errors;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;


@Slf4j
@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
//    private final KakaoService kakaoService;
//    private final NaverService naverService;
    private final JwtTokenProvider jwtTokenProvider;
    private final Response response;

    //회원가입 요청 처리
    @PostMapping("/user/signup")
    public String registerUser(@Valid @RequestBody SignupRequestDto requestDto){
        String res = userService.registerUser(requestDto);
        if(res.equals("")){
            return "회원가입 성공";
        }else{
            return res;
        }
    }

//    //카카오 소셜 로그인
//    @GetMapping("/auth/kakao/callback")
//    public @ResponseBody SocialLoginInfoDto kakaoCallback(String code, HttpServletResponse response) {      //ResponseBody -> Data를 리턴해주는 컨트롤러 함수
//        return kakaoService.requestKakao(code, response);
//    }
//
//    //네이버 소셜 로그인
//    @GetMapping("/auth/naver/callback")
//    public @ResponseBody SocialLoginInfoDto naverCallback(String code, String state, HttpServletResponse response){
//        return naverService.requestNaver(code, state, response);
//    }

    //로그인 유저 정보
    @GetMapping("/user")
    public LoginIdCheckDto userDetails(@AuthenticationPrincipal UserDetailsImpl userDetails) {
        return userService.userInfo(userDetails);
    }

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(@Validated UserRequestDto.Reissue reissue, Errors errors) {
        // validation check
        if (errors.hasErrors()) {
            return response.invalidFields(Helper.refineErrors(errors));
        }
        return userService.reissue(reissue);
    }

}