package com.example.jwtandredis2.jwtwithRedis;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;


// 클라이언트 요청 시 JWT 인증을 하기 위해 설치하는 Custom Filter로
// UsernamePasswordAuthenticationFilter 이전에 실행
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_TYPE = "Bearer";

    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTemplate redisTemplate;
    private final Response response2;


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        // 1. Request Header에서 JWT 토큰 추출
        String accessToken = resolveToken((HttpServletRequest) request);
        System.out.println("액세스 토큰 추출 완료 " + accessToken);

        // 2. validationToken으로 토큰 유효성 검사
        if (accessToken != null) {
            if (jwtTokenProvider.validateToken(accessToken)) {
                System.out.println("액세스 토큰 유효성 검사 통과");
                // Redis에 해당 accessToken logout 여부 확인
                String isLogout = (String) redisTemplate.opsForValue().get(accessToken);

                if (ObjectUtils.isEmpty(isLogout)) {
                    // 토큰이 유효할 경우 토큰에서 Authentication 객체를 가지고 와서 SecurityContext에 저장
                    Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } else {
                // 토큰이 존재하지만 유효성 검사를 통과하지 못했을 경우 토큰 재발급
                regenerateAccessToken(accessToken);
            }
        }
        chain.doFilter(request, response);
    }


    // Request Header에서 토큰 정보 추출
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_TYPE)) {
            return bearerToken.substring(7);
        }
        return null;
    }

    // RefreshToken으로 AccessToken 재생성
    private ResponseEntity<?> regenerateAccessToken(String accessToken) throws ServletException, IOException {
        // 2. Access Token 에서 Username 을 가져옵니다.
        Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);

        // 3. Redis 에서 Username 을 기반으로 저장된 Refresh Token 값을 가져옵니다.
        String refreshToken = (String)redisTemplate.opsForValue().get("RT:" + authentication.getName());

        if (refreshToken == null) {
            return response2.fail("Refresh Token 정보가 일치하지 않습니다.", HttpStatus.BAD_REQUEST);
        }

        // 4. 새로운 Access 토큰 생성
        UserResponseDto.TokenInfo newAccessToken = jwtTokenProvider.regenerateAccessToken(authentication);

        System.out.println("access token : " + newAccessToken.getAccessToken());
        System.out.println("access token 재발급 완료");

        String username = authentication.getName();
        System.out.println(username);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        return response2.success(newAccessToken, "Token 정보가 갱신되었습니다.", HttpStatus.OK);
    }
}