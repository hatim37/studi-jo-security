package com.ecom.security.service;

import com.ecom.security.clients.ValidationRestClient;
import com.ecom.security.entity.DevicesId;
import com.ecom.security.entity.JwtUser;
import com.ecom.security.model.User;
import com.ecom.security.model.Validation;
import com.ecom.security.repository.DevicesIdRepository;
import com.ecom.security.repository.JwtRepository;
import com.ecom.security.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class JwtServiceIntegrationTest {

    @Spy
    @InjectMocks
    private JwtService jwtService;

    @Mock
    private JwtRepository jwtRepository;

    @Mock
    private DevicesIdRepository devicesRepository;

    @Mock
    private ValidationRestClient validationRestClient;

    @Mock
    private TokenMicroService tokenMicroService;

    // Trois types d’utilisateurs
    private User activeUser;
    private User inactiveUser;
    private User adminUser;

    // On transforme les utilisateurs pour Spring Security
    private UserDetailsImpl activeUserDetails;
    private UserDetailsImpl inactiveUserDetails;
    private UserDetailsImpl adminUserDetails;

    // Simule un device déjà enregistré dans la BDD
    private DevicesId existingDevice;

    @BeforeEach
    void setUp() {
        // Initialise
        MockitoAnnotations.openMocks(this);

        // Création d'un utilisateur actif
        activeUser = new User();
        activeUser.setId(1L);
        activeUser.setEmail("user@domain.com");
        activeUser.setActive(true);
        activeUser.setUsername("user");
        activeUser.setName("Regular User");

        // Création d'un utilisateur inactif
        inactiveUser = new User();
        inactiveUser.setId(2L);
        inactiveUser.setEmail("inactive@domain.com");
        inactiveUser.setActive(false);
        inactiveUser.setUsername("inactive");
        inactiveUser.setName("Inactive User");

        // Création d'un utilisateur admin
        adminUser = new User();
        adminUser.setId(3L);
        adminUser.setEmail("admin@admin.com");
        adminUser.setActive(true);
        adminUser.setUsername("admin");
        adminUser.setName("Admin");

        // On renseigne le UserDetailsImpl pour JwtService
        activeUserDetails = new UserDetailsImpl(activeUser);
        inactiveUserDetails = new UserDetailsImpl(inactiveUser);
        adminUserDetails = new UserDetailsImpl(adminUser);

        // Simulation d’un device déjà présent en BDD
        existingDevice = new DevicesId();
        existingDevice.setId(100L);
        existingDevice.setUserId(activeUser.getId());
        existingDevice.setDeviceId("device-123");
        existingDevice.setActive(true);

        // On simule la réponse du service de tokenTechnique
        when(tokenMicroService.tokenService()).thenReturn("mocked-token");

        // On simule la méthode generateJwt
        doAnswer(invocation -> {
            User userArg = invocation.getArgument(0);
            return Map.of("bearer", "mocked-jwt-token");
        }).when(jwtService).generateJwt(any(User.class));

        // Simule le comportement du repo de devices
        when(devicesRepository.findByDeviceId("device-123")).thenReturn(Optional.of(existingDevice)); // device existant
        when(devicesRepository.findByDeviceId("new-device")).thenReturn(Optional.empty());            // device inconnu

        // Simule l'envoi d'un code de validation
        when(validationRestClient.sendValidation(anyString(), any())).thenReturn(new Validation(999L));
    }

    // Cas 1 : utilisateur actif avec un device déjà enregistré
    @Test
    void testGenerate_ExistingDevice_ReturnsOk() {

        ResponseEntity<Map<String, String>> response =
                jwtService.generate(activeUserDetails, "device-123");

        // Vérification, status 200 +token retourné + save
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("mocked-jwt-token", response.getBody().get("bearer"));
        verify(jwtRepository).save(any(JwtUser.class));
    }

    // Cas 2 : utilisateur actif avec un NOUVEAU device
    @Test
    void testGenerate_NewDevice_ReturnsForbidden() {

        ResponseEntity<Map<String, String>> response =
                jwtService.generate(activeUserDetails, "new-device");

        // Vérification, code 403 FORBIDDEN + UUID ok + status pending
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertNotNull(response.getBody().get("uuid"));
        verify(jwtRepository).save(any(JwtUser.class));
    }

    // Cas 3 : utilisateur inactif essaye de générer un token
    @Test
    void testGenerate_InactiveDevice_ReturnsForbidden() {
        Exception exception = assertThrows(
                RuntimeException.class,
                () -> jwtService.generate(inactiveUserDetails, "device-123")
        );

        // Vérification, message : compte inactif + token non save
        assertTrue(exception.getMessage().contains("Compte non activé"));
        verify(jwtRepository, never()).save(any(JwtUser.class));
    }

    // Cas 4 : utilisateur ADMIN sans deviceId
    @Test
    void testGenerate_AdminUser_ReturnsOk() {
        ResponseEntity<Map<String, String>> response =
                jwtService.generate(adminUserDetails, null);

        // Vérification, status 200 + token + save
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("mocked-jwt-token", response.getBody().get("bearer"));
        verify(jwtRepository).save(any(JwtUser.class));
    }
}

