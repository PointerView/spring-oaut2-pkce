package com.pointerview.api.authorization_server.persistence.repository.security;

import com.pointerview.api.authorization_server.persistence.entity.security.ClientApp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ClientAppRepository extends JpaRepository<ClientApp, Long> {

    Optional<ClientApp> findByClientId(String clientId);

}
