package com.ecom.security.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.ecom.security.entity.DevicesId;
import com.ecom.security.entity.JwtUser;
import com.ecom.security.model.Role;
import com.ecom.security.model.Validation;
import com.ecom.security.response.UserNotFoundException;
import com.ecom.security.security.JwtService;
import com.ecom.security.model.User;
import com.ecom.security.config.JwtConfig;
import com.ecom.security.clients.ValidationRestClient;
import com.ecom.security.repository.DevicesIdRepository;
import com.ecom.security.repository.JwtRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import java.util.*;
import java.util.stream.Stream;

class JwtServiceTest {

    @Mock
    private JwtRepository jwtRepository;

    @Mock
    private DevicesIdRepository devicesRepository;

    @Mock
    private ValidationRestClient validationRestClient;

    @Mock
    private TokenMicroService tokenMicroService;

    @Mock
    private JwtConfig jwtConfig;

    @InjectMocks
    private JwtService jwtService;


    @Mock
    private JwtEncoder jwtEncoder;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    // 1 : ADMIN qui n'a pas besoin de deviceID
    @Test
    void testGenerate_AdminUser_ReturnsOk() {
        // Préparation des données
        User admin = new User();
        admin.setId(1L);
        admin.setEmail("admin@admin.com");
        admin.setActive(true);
        admin.setName("Admin");
        admin.setUsername("adminUser");

        // On simule des UserDetails
        UserDetails userDetails = mock(UserDetailsImpl.class);
        when(((UserDetailsImpl) userDetails).getUser()).thenReturn(admin);

        // On remplace génération JWT pour simuler des tokens
        Map<String, String> jwtMap = Map.of("bearer", "fakeToken");
        JwtService spyService = spy(jwtService);
        doReturn(jwtMap).when(spyService).generateJwt(admin);

        // Exécution
        ResponseEntity<Map<String, String>> response = spyService.generate(userDetails, null);

        // Vérifications
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(jwtMap, response.getBody());
        verify(jwtRepository).save(any(JwtUser.class));
    }

    // 2 : Utilisateur inactif ave le cas du service de validation indisponible
    @Test
    void testGenerate_InactiveUser_ServiceIndisponible() {
        // Préparation des données
        User user = new User();
        user.setEmail("user@test.com");
        user.setActive(false);
        UserDetailsImpl userDetails = new UserDetailsImpl(user);

        // Le service validation ne renvoie rien
        Validation validation = new Validation();
        when(tokenMicroService.tokenService()).thenReturn("mockToken");
        when(validationRestClient.sendValidation(anyString(), any()))
                .thenReturn(validation);

        // Exécution + Vérification que l'exception est levée
        UserNotFoundException ex = assertThrows(UserNotFoundException.class,
                () -> jwtService.generate(userDetails, "device123"));

        assertEquals("Service indisponible", ex.getMessage());
    }

    // 3 : Utilisateur inactif avec service de validation OK
    @Test
    void testGenerate_InactiveUser_CompteNonActive() {
        // Préparation des données
        User user = new User();
        user.setEmail("user@test.com");
        user.setActive(false);
        UserDetailsImpl userDetails = new UserDetailsImpl(user);

        // Cette fois, le service de validation renvoie un id
        Validation validation = new Validation();
        validation.setId(999L);

        when(tokenMicroService.tokenService()).thenReturn("mockToken");
        when(validationRestClient.sendValidation(anyString(), any()))
                .thenReturn(validation);

        // Exécution + vérification que du retour validation et exception levée avec message
        UserNotFoundException ex = assertThrows(UserNotFoundException.class,
                () -> jwtService.generate(userDetails, "device123"));
        // Vérification
        assertTrue(ex.getMessage().contains("Compte non activé"));
        assertEquals("999", ex.getDetails());
    }

    // 4 : deviceId null avec levée d'une exception
    @Test
    void testGenerate_NullDeviceId_ThrowsException() {
        // Préparation d'un user
        User user = new User();
        user.setId(3L);
        user.setEmail("user@test.com");
        user.setActive(true);
        user.setUsername("user");

        UserDetails userDetails = mock(UserDetailsImpl.class);
        when(((UserDetailsImpl) userDetails).getUser()).thenReturn(user);

        // Exécution + Vérification exception
        UserNotFoundException ex = assertThrows(UserNotFoundException.class,
                () -> jwtService.generate(userDetails, null));
        // Vérifications
        assertEquals("Navigateur non reconnu", ex.getMessage());
    }

    // 5 : Nouvel appareil détecté retour FORBIDDEN
    @Test
    void testGenerate_NewDevice_ReturnsForbidden() {
        // Préparation
        User user = new User();
        user.setId(4L);
        user.setEmail("user@test.com");
        user.setActive(true);
        user.setUsername("user");

        UserDetails userDetails = mock(UserDetailsImpl.class);
        when(((UserDetailsImpl) userDetails).getUser()).thenReturn(user);

        // Le device n'existe pas encore
        when(devicesRepository.findByDeviceId("device123")).thenReturn(Optional.empty());
        when(tokenMicroService.tokenService()).thenReturn("mockToken");
        when(validationRestClient.sendValidation(anyString(), any())).thenReturn(new Validation(10L));

        JwtService spyService = spy(jwtService);
        doReturn(Map.of("bearer", "fakeToken")).when(spyService).generateJwt(user);

        // Exécution
        ResponseEntity<Map<String, String>> response = spyService.generate(userDetails, "device123");

        // Vérifications
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertTrue(response.getBody().containsKey("error"));
        assertEquals("Nouvel appareil détecté", response.getBody().get("error"));
        assertEquals("10", response.getBody().get("option"));
    }

    // 6 : Appareil existant mais non validé =  FORBIDDEN
    @Test
    void testGenerate_ExistingInactiveDevice_ReturnsForbidden() {
        // Préparation
        User user = new User();
        user.setId(6L);
        user.setEmail("user@test.com");
        user.setActive(true);
        user.setUsername("user");

        DevicesId device = new DevicesId();
        device.setDeviceId("device123");
        device.setActive(false);
        device.setUserId(user.getId());

        UserDetails userDetails = mock(UserDetailsImpl.class);
        when(((UserDetailsImpl) userDetails).getUser()).thenReturn(user);

        when(devicesRepository.findByDeviceId("device123")).thenReturn(Optional.of(device));
        when(tokenMicroService.tokenService()).thenReturn("mockToken");
        when(validationRestClient.sendValidation(anyString(), any())).thenReturn(new Validation(20L));

        JwtService spyService = spy(jwtService);
        doReturn(Map.of("bearer", "fakeToken")).when(spyService).generateJwt(user);

        // Exécution
        ResponseEntity<Map<String, String>> response = spyService.generate(userDetails, "device123");

        // Vérifications
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertTrue(response.getBody().containsKey("error"));
        assertEquals("Nouvel appareil détecté", response.getBody().get("error"));
        assertEquals("20", response.getBody().get("option"));
    }

    // 7 : Appareil déjà validé, génération de token
    @Test
    void testGenerate_ExistingActiveDevice_ReturnsOk() {
        // Préparation
        User user = new User();
        user.setId(5L);
        user.setEmail("user@test.com");
        user.setActive(true);
        user.setUsername("user");

        DevicesId device = new DevicesId();
        device.setDeviceId("device123");
        device.setActive(true);
        device.setUserId(user.getId());

        UserDetails userDetails = mock(UserDetailsImpl.class);
        when(((UserDetailsImpl) userDetails).getUser()).thenReturn(user);

        when(devicesRepository.findByDeviceId("device123")).thenReturn(Optional.of(device));

        JwtService spyService = spy(jwtService);
        doReturn(Map.of("bearer", "fakeToken")).when(spyService).generateJwt(user);

        // Exécution
        ResponseEntity<Map<String, String>> response = spyService.generate(userDetails, "device123");

        // Vérifications
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(Map.of("bearer", "fakeToken"), response.getBody());
    }

    // 8 : Désactivation de tous les anciens tokens d'un utilisateur
    @Test
    void testDisableTokens_callsFindUserAndDeleteAll() {
        // Préparation
        User user = new User();
        user.setId(42L);

        JwtUser j1 = new JwtUser();
        j1.setId(1);
        j1.setUserId(42L);
        j1.setToken("t1");

        JwtUser j2 = new JwtUser();
        j2.setId(2);
        j2.setUserId(42L);
        j2.setToken("t2");

        // On simule que la méthode findUser renvoie deux tokens actifs
        when(jwtRepository.findUser(user.getId())).thenReturn(Stream.of(j1, j2));

        // Exécution
        jwtService.disableTokens(user);

        // Vérification que les bonnes méthodes sont appelées
        verify(jwtRepository, times(1)).findUser(user.getId());

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<JwtUser>> captor = ArgumentCaptor.forClass((Class) List.class);
        verify(jwtRepository, times(1)).deleteAll(captor.capture());

        List<JwtUser> deleted = captor.getValue();
        assertNotNull(deleted);
        assertEquals(2, deleted.size());
        assertTrue(deleted.contains(j1));
        assertTrue(deleted.contains(j2));
    }

    // 9 : Génération d'un JWT valide
    @Test
    void testGenerateJwt_ReturnsTokenMap() {
        // Préparation
        User user = new User();
        user.setId(10L);
        user.setEmail("user@test.com");
        user.setUsername("user");
        user.setName("Test User");
        user.setRoles(List.of(new Role("ROLE_USER")));
        user.setActive(true);

        JwtEncoder mockEncoder = mock(JwtEncoder.class);
        Jwt jwt = mock(Jwt.class);

        // Simule l'encodage d'un JWT qui renvoie "fakeToken"
        when(jwt.getTokenValue()).thenReturn("fakeToken");
        when(mockEncoder.encode(any())).thenReturn(jwt);
        when(jwtConfig.userJwtEncoder()).thenReturn(mockEncoder);

        JwtService spyService = spy(jwtService);

        // Exécution
        Map<String, String> result = spyService.generateJwt(user);

        // Vérifications
        assertNotNull(result);
        assertEquals("fakeToken", result.get("bearer"));
    }

    // 10 : Suppression périodique des anciens tokens expirés
    @Test
    void testRemoveUselessJwt_CallsRepositoryDelete() {
        // Exécution
        jwtService.removeUselessJwt();

        // Vérification que la méthode de suppression est bien appelée
        verify(jwtRepository, times(1))
                .deleteAllByExpireAtAndDesactive(true, true);
    }

}

