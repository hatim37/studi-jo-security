package com.ecom.security.entity;

import com.ecom.security.model.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "user_device")
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
public class DevicesId {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Lob
    private String deviceId;
    private Instant createdAt;
    private Boolean active=false;
    @Transient
    private User user;
    private Long userId;
}
