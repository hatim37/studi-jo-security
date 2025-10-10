package com.ecom.security.model;

import lombok.*;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class Role {

    private int id;
    private String name;

    public Role(String roleUser) {
    }
}
