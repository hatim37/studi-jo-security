package com.ecom.security.service;


import com.ecom.security.clients.UserRestClient;
import com.ecom.security.model.User;
import com.ecom.security.response.UserNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
@Slf4j
@Service
public class UserDetailsServiceImpl implements UserDetailsService {


    @Autowired
    private UserRestClient userRepository;
    @Autowired
    private TokenMicroService tokenMicroService;


    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        String token = this.tokenMicroService.tokenService();
        String bearer = "Bearer " + token;

        User user = userRepository.findByEmailLogin(bearer,email);
        if (user.getName().contains("non trouvé")) {
            throw new UserNotFoundException("Email ou mot de passe invalide load");
        }
        return new UserDetailsImpl(user);
    }
}
