package com.ecom.security.service;


import com.ecom.security.dto.LoginActivationDto;
import com.ecom.security.entity.DevicesId;
import com.ecom.security.repository.DevicesIdRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class ActivationDeviceIdService {

    public ActivationDeviceIdService(DevicesIdRepository devicesRepository) {
        this.devicesRepository = devicesRepository;
    }

    private final DevicesIdRepository devicesRepository;


    public void activationDeviceIdService(LoginActivationDto loginActivationDto) {
        Optional<DevicesId> optionalUserDevices = this.devicesRepository.findById(loginActivationDto.getDeviceId());
        if (optionalUserDevices.isPresent()) {
            DevicesId userDevices = optionalUserDevices.get();
            userDevices.setActive(true);
            devicesRepository.save(userDevices);
        }
    }


}
