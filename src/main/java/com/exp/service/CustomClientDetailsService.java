package com.exp.service;

import com.exp.domain.Client;
import com.exp.domain.ClientAdapter;
import com.exp.repository.ClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.stereotype.Service;

/**
 * Created by rohith on 19/2/18.
 */
@Service
public class CustomClientDetailsService implements ClientDetailsService {

    private ClientRepository clientRepository;

    @Autowired
    public CustomClientDetailsService(ClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    @Override
    public ClientDetails loadClientByClientId(String s) throws ClientRegistrationException {
        Client client = clientRepository.findOne(s);
        if(client == null) {
            throw new ClientRegistrationException("Client not found");
        }
        return new ClientAdapter(client);
    }

    public Client saveClient(Client client) {
        return clientRepository.save(client);
    }

}
