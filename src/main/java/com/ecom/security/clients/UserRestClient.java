package com.ecom.security.clients;


import com.ecom.security.model.User;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.List;



@FeignClient(name = "users-service", url = "${users.service.url}")
public interface UserRestClient {

    @GetMapping("/users/{id}")
    @CircuitBreaker(name="users", fallbackMethod = "getDefaultUser")
    User findUserById(@PathVariable Long id);

    @GetMapping("/users")
    @CircuitBreaker(name="users", fallbackMethod = "getAllUser")
    List<User> allUsers();

    @GetMapping("/users-email/{email}")
    @CircuitBreaker(name="users", fallbackMethod = "getDefaultEmail")
    User findByEmail( @PathVariable String email);

    @GetMapping("/_internal/users-login/{email}")
    @CircuitBreaker(name="users", fallbackMethod = "getDefaultEmailLogin")
    User findByEmailLogin(@RequestHeader("Authorization") String authorization,@PathVariable String email);

   default User getDefaultUser(Long id, Exception e) {
       User user = new User();
       user.setId(id);
       user.setName("default");
       user.setEmail("default@email.com");
       user.setActive(false);
       user.setRoles(List.of());
       return user;
   }

    default User getDefaultEmail(String email, Exception e) {
        User user = new User();
        user.setId(Long.valueOf("0"));
        user.setName("non trouvée");
        user.setEmail(email);
        user.setActive(false);
        user.setRoles(List.of());
        return user;
    }

    default User getDefaultEmailLogin(String authorization, String email, Exception e) {
        User user = new User();
        user.setId(Long.valueOf("0"));
        user.setName("non trouvée");
        user.setEmail(email);
        user.setActive(false);
        user.setRoles(List.of());
        return user;
    }

    default List<User> getAllUser(Exception exception){
        return List.of();
    }
}
