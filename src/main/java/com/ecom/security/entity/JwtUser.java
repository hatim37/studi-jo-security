package com.ecom.security.entity;

import com.ecom.security.model.User;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Entity
@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "jwt")
public class JwtUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(length = 600)
    private String token;
    private Boolean desactive;
    private Boolean expireAt;
    private Boolean pending=false;
    private UUID uuid;
    @Transient
    private User user;
    private Long userId;
}
