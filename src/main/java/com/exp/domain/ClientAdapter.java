package com.exp.domain;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * Created by rohith on 19/2/18.
 */
public class ClientAdapter implements ClientDetails {

    private static final long serialVersionUID = -1360188333928173333L;

    private Client client;

    public ClientAdapter(Client client) {
        this.client = client;
    }


    @Override
    public String getClientId() {
        return client.getClientId();
    }

    @Override
    public Set<String> getResourceIds() {
        return client.getResourceIds();
    }

    @Override
    public boolean isSecretRequired() {
        return client.isSecretRequired();
    }

    @Override
    public String getClientSecret() {
        return client.getClientSecret();
    }

    @Override
    public boolean isScoped() {
        return client.isScoped();
    }

    @Override
    public Set<String> getScope() {
        return client.getScope();
    }

    @Override
    public Set<String> getAuthorizedGrantTypes() {
        return client.getAuthorizedGrantTypes();
    }

    @Override
    public Set<String> getRegisteredRedirectUri() {
        return client.getRegisteredRedirectUri();
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
    	
    	Collection<GrantedAuthority> authorities = new ArrayList<>();
    	authorities.add(new GrantedAuthority() {
			
			@Override
			public String getAuthority() {
				return "ROLE_ADMIN";
			}
		});
    	
        return authorities;
    }

    @Override
    public Integer getAccessTokenValiditySeconds() {
        return client.getAccessTokenValiditySeconds();
    }

    @Override
    public Integer getRefreshTokenValiditySeconds() {
        return client.getRefreshTokenValiditySeconds();
    }

    @Override
    public boolean isAutoApprove(String s) {
        return true;
    }

    @Override
    public Map<String, Object> getAdditionalInformation() {
        return null;
    }
}
