package com.ecom.security.repository;


import com.ecom.security.entity.JwtUser;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

public interface JwtRepository extends CrudRepository<JwtUser, Integer> {

    Optional<JwtUser> findByTokenAndDesactiveAndExpireAt(String valeur, boolean desactive, boolean expire);

    @Query("FROM JwtUser j WHERE j.expireAt = :expireAt AND j.desactive = :desactive AND j.userId = :id")
    Optional<JwtUser> findUserValidToken(Long id, boolean desactive, boolean expireAt);

    @Query("FROM JwtUser j WHERE j.userId = :id")
    Stream<JwtUser> findUser(Long id);

    void deleteAllByExpireAtAndDesactive(boolean expire, boolean desactive);

    Optional<JwtUser> findByUuid(UUID uuid);
}
