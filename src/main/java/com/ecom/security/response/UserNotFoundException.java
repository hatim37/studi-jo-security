package com.ecom.security.response;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@Getter
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class UserNotFoundException extends RuntimeException{
    private final String details;

    public UserNotFoundException(String message) {
        super(message);
        this.details = null;
    }

    public UserNotFoundException(String message, String details) {
        super(message);
        this.details = details;
    }

}
