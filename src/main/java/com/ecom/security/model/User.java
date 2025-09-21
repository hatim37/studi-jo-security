package com.ecom.security.model;


import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Getter @Setter @ToString
public class User  {

    private Long id;
    private String name;
    private String username;
    private String password;
    private String email;
    private Boolean active;
    private Collection<Role> roles;

    public String getAuthorities() {
        return Optional.ofNullable(roles)
                .orElse(List.of()) // liste vide si null
                .stream()
                .map(Role::getName)
                .collect(Collectors.joining(" "));
    }

    public boolean getActive() {
        return this.active;
    }

}
