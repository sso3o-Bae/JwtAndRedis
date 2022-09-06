package com.example.jwtandredis2.config;




import com.example.jwtandredis2.config.jwt.FormLoginFilter;
import com.example.jwtandredis2.jwtwithRedis.JwtAuthenticationFilter;
import com.example.jwtandredis2.jwtwithRedis.JwtTokenProvider;
import com.example.jwtandredis2.jwtwithRedis.Response;

import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


@Configuration
@EnableWebSecurity// 시큐리티 활성화 -> 기본 스프링 필터체인에 등록
@EnableGlobalMethodSecurity(securedEnabled = true)
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{


    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTemplate redisTemplate;
    private final Response response2;

    @Bean   // 비밀번호 암호화
    public BCryptPasswordEncoder encodePassword() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override // Bean 에 등록
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    // 정적 자원에 대해서는 Security 설정을 적용하지 않음.
    @Override
    public void configure(WebSecurity web) {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        String password = encodePassword().encode("1234");
//        auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN");
//    }

//    @Bean
//    public PasswordEncoder passwordEncoder(){
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors();
        http.csrf().disable();
        http.headers().frameOptions().disable();

        http.authorizeRequests()
                // api 요청 접근허용
                .antMatchers("/h2-console/**").permitAll()
                .antMatchers(HttpMethod.POST,"/items").access("hasRole('ADMIN')")
                .antMatchers("/").permitAll()
                .antMatchers("/**").permitAll()
//                .antMatchers("product/basketList").authenticated()
//                .antMatchers(HttpMethod.POST,"product/comment").authenticated()
//                .antMatchers(HttpMethod.DELETE,"product/comment").authenticated()

                // 그 외 모든 요청허용
                .anyRequest().permitAll()
                .and()

                // 토큰을 활용하면 세션이 필요 없으므로 STATELESS로 설정하여 Session을 사용하지 않는다.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()

                .addFilterBefore(new FormLoginFilter(authenticationManager(), jwtTokenProvider, redisTemplate), UsernamePasswordAuthenticationFilter.class)
//                .addFilterBefore(new JwtAuthorizationFilter(authenticationManager(), userRepository), UsernamePasswordAuthenticationFilter.class)
                // JwtAuthenticationFilter를 UsernamePasswordAuthentictaionFilter 전에 적용시킨다.
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider, redisTemplate, response2), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // 수정 필요
        configuration.addAllowedOrigin("http://localhost:3000");
        configuration.addAllowedOrigin("http://localhost:3001");
        configuration.addAllowedOrigin("http://dontbeweak.s3-website.ap-northeast-2.amazonaws.com/");
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.addExposedHeader("Authorization");
        configuration.setAllowCredentials(true);
        // configuration.addAllowedOriginPattern("");
        // configuration.addAllowedOrigin("프론트 주소"); // 배포 시

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}