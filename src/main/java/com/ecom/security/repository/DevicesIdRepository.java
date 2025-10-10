package com.ecom.security.repository;

import com.ecom.security.entity.DevicesId;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DevicesIdRepository extends JpaRepository<DevicesId, Integer> {

    Optional<DevicesId> findByDeviceId(String deviceId);

    Optional<DevicesId> findById(Long id);


}
