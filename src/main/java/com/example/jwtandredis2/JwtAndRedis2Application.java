package com.example.jwtandredis2;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableCaching
@EnableJpaAuditing
@SpringBootApplication
public class JwtAndRedis2Application {

    public static final String APPLICATION_LOCATIONS = "spring.config.location="
            + "classpath:application-jwt.yml,"
            + "classpath:application.yml";

    public static void main(String[] args) {
        new SpringApplicationBuilder(JwtAndRedis2Application.class)
                .properties(APPLICATION_LOCATIONS)
                .run(args);
    }

}
