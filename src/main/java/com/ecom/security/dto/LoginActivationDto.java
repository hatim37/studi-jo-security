package com.ecom.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class LoginActivationDto {
    private Long userId;
    private Long deviceId;
    private Boolean active;
}
