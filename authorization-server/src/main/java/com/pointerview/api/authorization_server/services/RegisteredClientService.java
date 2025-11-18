package com.pointerview.api.authorization_server.services;

import com.pointerview.api.authorization_server.exceptions.ObjectNotFoundException;
import com.pointerview.api.authorization_server.mapper.ClientAppMapper;
import com.pointerview.api.authorization_server.persistence.entity.security.ClientApp;
import com.pointerview.api.authorization_server.persistence.repository.security.ClientAppRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

public class RegisteredClientService implements RegisteredClientRepository {

    @Autowired
    private ClientAppRepository clientAppRepository;

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    @Override
    public RegisteredClient findById(String id) {
        ClientApp clientApp = clientAppRepository.findByClientId(id)
                .orElseThrow(() -> new ObjectNotFoundException("Client not found"));
        return ClientAppMapper.toRegisteredClient(clientApp);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return this.findById(clientId);
    }
}
