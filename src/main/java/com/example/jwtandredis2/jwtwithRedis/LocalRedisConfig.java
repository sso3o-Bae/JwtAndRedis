package com.example.jwtandredis2.jwtwithRedis;

//
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Profile;
//import redis.embedded.RedisServer;
//
//import javax.annotation.PostConstruct;
//import javax.annotation.PreDestroy;
//import java.io.IOException;
//
//// Local 환경에서 Springboot 내장 redis로 테스트하기 위한 설정
//@Slf4j
//@Profile("local")
//@Configuration
//public class LocalRedisConfig {
//    @Value("${spring.redis.port}")
//    private int redisPort;
//
//    private RedisServer redisServer;
//
//    @PostConstruct
//    public void redisServer() throws IOException {
//        redisServer = new RedisServer(redisPort);
//        redisServer.start();
//    }
//
//    @PreDestroy
//    public void stopRedis() {
//        if (redisServer != null) {
//            redisServer.stop();
//        }
//    }
//
//}