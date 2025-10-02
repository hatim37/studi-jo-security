package com.ecom.security.controller;



import com.ecom.security.clients.UserRestClient;
import com.ecom.security.dto.AuthentificationDTO;
import com.ecom.security.entity.JwtUser;
import com.ecom.security.model.User;
import com.ecom.security.repository.JwtRepository;
import com.ecom.security.response.UserNotFoundException;
import com.ecom.security.security.JwtService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@RestController
public class LoginController {

    private final UserRestClient userRestClient;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final JwtRepository jwtRepository;

    public LoginController(UserRestClient userRestClient, AuthenticationManager authenticationManager, JwtService jwtService, JwtRepository jwtRepository) {
        this.userRestClient = userRestClient;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.jwtRepository = jwtRepository;
    }

    @PostMapping(path = "/signin")
    public ResponseEntity<Map<String, String>> signin(@RequestBody AuthentificationDTO authentificationDTO){

        Authentication authenticate = null;
        try {
            authenticate = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authentificationDTO.username(), authentificationDTO.password())
            );
            if(authenticate.isAuthenticated()){
                UserDetails userDetails = (UserDetails) authenticate.getPrincipal();
                return this.jwtService.generate(userDetails, authentificationDTO.devices());
            }
        } catch (AuthenticationException e) {
            throw new UserNotFoundException("Email ou mot de passe invalide");
        }
        throw new UserNotFoundException("Authentification a échouée");
    }

    @PostMapping(path="/signin-validation")
    public ResponseEntity<Map<String, String>> signinValidation(@RequestBody Map<String, String> uuidString){
        UUID uuid = UUID.fromString(uuidString.get("uuid").trim());
        Optional<JwtUser> jwt = this.jwtRepository.findByUuid(uuid);
        if (jwt.isPresent() && jwt.get().getPending()) {
            String token = jwt.get().getToken();
            jwt.get().setPending(false);
            jwtRepository.save(jwt.get());
            return new ResponseEntity<>(Map.of("bearer",token), HttpStatus.OK);
        } else {
            throw new UserNotFoundException("Service indisponible");
        }
    }


    @GetMapping(path = "/users")
    @PreAuthorize("hasAuthority('SCOPE_AMDIN')")
    public List<User> getUsers() {
        return userRestClient.allUsers();
    }

    @GetMapping("/users/{id}")
    public User customerById(@PathVariable Long id){
        return userRestClient.findUserById(id);
    }

    @GetMapping("/users-email/{email}")
    public User customerByEmail(@PathVariable String email){
        return userRestClient.findByEmail(email);
    }



}
