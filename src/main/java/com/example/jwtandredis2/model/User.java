package com.example.jwtandredis2.model;



import com.example.jwtandredis2.common.BaseEntity;

import lombok.*;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Builder
@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class User extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column
    private String nickname;

    @Column
    private String oauth;


    private String role;


    public User(String username, String password, String nickname) {
        this.username = username;
        this.password = password;
        this.nickname = nickname;
    }

    public User(String username, String password, String oauth, String nickname) {
        this.username = username;
        this.password = password;
        this.oauth = oauth;
        this.nickname = nickname;
    }

}