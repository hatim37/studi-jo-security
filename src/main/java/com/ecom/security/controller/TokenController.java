package com.ecom.security.controller;

import com.ecom.security.service.TokenMicroService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class TokenController {

    private final TokenMicroService tokenMicroService;

    public TokenController(TokenMicroService tokenMicroService) {
        this.tokenMicroService = tokenMicroService;
    }

    @GetMapping(path = "/token")
    public String generateTechnicalToken() {
       return this.tokenMicroService.tokenService();
    }
}
