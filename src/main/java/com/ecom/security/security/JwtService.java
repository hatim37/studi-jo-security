package com.ecom.security.security;

import com.ecom.security.clients.ValidationRestClient;
import com.ecom.security.config.JwtConfig;
import com.ecom.security.dto.ValidationDto;
import com.ecom.security.entity.DevicesId;
import com.ecom.security.entity.JwtUser;
import com.ecom.security.model.User;
import com.ecom.security.model.Validation;
import com.ecom.security.repository.DevicesIdRepository;
import com.ecom.security.repository.JwtRepository;
import com.ecom.security.response.UserNotFoundException;
import com.ecom.security.service.TokenMicroService;
import com.ecom.security.service.UserDetailsImpl;
import com.ecom.security.service.UserDetailsServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Transactional
@Slf4j
@Service
public class JwtService {
    public static final String BAERER = "bearer";
    public static final String REFRESH_TOKEN = "refreshToken";

    private final DevicesIdRepository devicesRepository;
    private final JwtRepository jwtRepository;
    private final JwtConfig jwtConfig;
    private final ValidationRestClient validationRestClient;
    private final TokenMicroService tokenMicroService;

    public JwtService(JwtConfig jwtConfig, JwtRepository jwtRepository, DevicesIdRepository devicesRepository, ValidationRestClient validationRestClient, TokenMicroService tokenMicroService) {
        this.jwtConfig = jwtConfig;
        this.jwtRepository = jwtRepository;
        this.devicesRepository = devicesRepository;
        this.validationRestClient = validationRestClient;
        this.tokenMicroService = tokenMicroService;
    }

    public ResponseEntity<Map<String, String>> generate(UserDetails userDetails, String deviceId) {
        //je prepare un UUID
        UUID uuidToken = UUID.randomUUID();
        //je récupère l'utilisateur
        User user =null;
        if (userDetails instanceof UserDetailsImpl customUserDetails) {
            user = customUserDetails.getUser();
        } else {
            throw new UserNotFoundException("utilisateur non trouvée");
        }
        //autorisation ADMIN sans deviceID
        if ("admin@admin.com".equals(user.getEmail())) {
            this.disableTokens(user); // désactiver les anciens tokens
            final Map<String, String> jwtMap = this.generateJwt(user);

            JwtUser jwtUser = JwtUser.builder()
                    .token(jwtMap.get(BAERER))
                    .desactive(false)
                    .expireAt(false)
                    .uuid(uuidToken)
                    .userId(user.getId())
                    .build();

            jwtRepository.save(jwtUser);

            return new ResponseEntity<>(jwtMap, HttpStatus.OK);
        }

        //je verifie que le compte est actif
        if (!user.getActive()){

            //on renvoi un code de validation
            Validation validationId = this.validationRestClient.sendValidation("Bearer "+this.tokenMicroService.tokenService(), new ValidationDto(user.getId(),user.getUsername(), null, user.getEmail(), "registration"));
            if(validationId.getId()==null){
                throw new UserNotFoundException("Service indisponible");
            }
            throw new UserNotFoundException("Compte non activé", validationId.getId().toString());
        }
        //je vérifie que le deviceId nous a bien été transmit
        if (deviceId == null) {
            throw new UserNotFoundException("Navigateur non reconnu");
        }


        //je verifie le deviceId existe en Bdd
        Optional<DevicesId> userDevices = this.devicesRepository.findByDeviceId(deviceId);
        //si le deviceId n'est pas present
        if (userDevices.isEmpty()){

            DevicesId newUserDevices = new DevicesId();
            newUserDevices.setDeviceId(deviceId);
            newUserDevices.setUserId(user.getId());
            newUserDevices.setActive(false);
            newUserDevices.setCreatedAt(Instant.now());
            this.devicesRepository.save(newUserDevices);

            //on envoie une demande de validation
            Validation validationId = this.validationRestClient.sendValidation("Bearer "+this.tokenMicroService.tokenService(),new ValidationDto(user.getId(),user.getUsername(), newUserDevices.getId(), user.getEmail(), "deviceId"));
            if(validationId.getId()==null){
                throw new UserNotFoundException("Service indisponible");
            }

            //je désactive tous les anciens token en Bdd
            this.disableTokens(user);
            //je genere le token
            final Map<String, String> jwtMap = this.generateJwt(user);
            //j'ajoute le token en bbd
            JwtUser jwtUser = JwtUser
                    .builder()
                    .token(jwtMap.get(BAERER))
                    .desactive(false)
                    .expireAt(false)
                    .pending(true)
                    .uuid(uuidToken)
                    .userId(user.getId())
                    .build();
            //je sauvegarde
            jwtRepository.save(jwtUser);

            return new ResponseEntity<>(Map.of(
                            "error", "Nouvel appareil détecté",
                            "option", validationId.getId().toString(),
                            "uuid", uuidToken.toString()), HttpStatus.FORBIDDEN);
            //si le deviceId est present mais pas validé
        } if (!userDevices.get().getActive()) {
            //on envoi une validation mail
            Validation validationId = this.validationRestClient.sendValidation("Bearer "+this.tokenMicroService.tokenService(),new ValidationDto(user.getId(),user.getUsername(), userDevices.get().getId(), user.getEmail(), "deviceId"));
            if(validationId.getId()==null){
                throw new UserNotFoundException("Service indisponible");
            }
            return new ResponseEntity<>(Map.of(
                    "error", "Nouvel appareil détecté",
                    "option", validationId.getId().toString(),
                    "uuid", uuidToken.toString()), HttpStatus.FORBIDDEN);
        }

        //je désactive tous les anciens token en Bdd
        this.disableTokens(user);
        //je génère le token
        final Map<String, String> jwtMap = this.generateJwt(user);
        //j'ajoute le token en bbd
        JwtUser jwtUser = JwtUser
                .builder()
                .token(jwtMap.get(BAERER))
                .desactive(false)
                .expireAt(false)
                .userId(user.getId())
                .build();
        //je sauvegarde
        jwtRepository.save(jwtUser);
        return new ResponseEntity<>(this.generateJwt(user), HttpStatus.OK);

    }

    private Map<String, String> generateJwt(User user) {
        Map<String, String> idToken = new HashMap<>();
        Instant instant = Instant.now();
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .subject(user.getEmail())
                .issuedAt(instant)
                .expiresAt(instant.plus(30, ChronoUnit.MINUTES))
                .issuer("security-service")
                .claim("scope",user.getAuthorities())
                .claim("name", user.getName())
                .claim("username", user.getUsername())
                .claim("id", user.getId())
                .build();
        String jwtAccessToken = jwtConfig.userJwtEncoder().encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        idToken.put("accessToken", jwtAccessToken);

        return Map.of("bearer", jwtAccessToken);
    }


    private void disableTokens(User user) {
        final List<JwtUser> jwtList = this.jwtRepository.findUser(user.getId()).collect(Collectors.toList());
        this.jwtRepository.deleteAll(jwtList);
    }




    @Scheduled(cron= "@monthly")
    public void removeUselessJwt(){
        this.jwtRepository.deleteAllByExpireAtAndDesactive(true, true);
    }

}





