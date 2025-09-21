package com.ecom.security.clients;


import com.ecom.security.dto.ValidationDto;
import com.ecom.security.model.Validation;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@FeignClient(name = "validation-service", url = "${validation.service.url}")
public interface ValidationRestClient {

    @PostMapping("/_internal/validation-send")
    @CircuitBreaker(name="validation", fallbackMethod = "getDefaultValidation")
    Validation sendValidation(@RequestHeader("Authorization") String authorization, @RequestBody ValidationDto validationDto);

   default Validation getDefaultValidation(String authorization, ValidationDto validationDto, Exception e) {
       Validation validation = new Validation();
       validation.setId(null);
       return validation;
   }



}
