package com.ecom.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Data
public class ValidationDto {
    private Long userId;
    private String username;
    private Long deviceId;
    private String email;
    private String type;
}
