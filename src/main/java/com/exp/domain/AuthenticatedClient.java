package com.exp.domain;

import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

public class AuthenticatedClient extends BaseClientDetails implements ClientDetails {

	private static final long serialVersionUID = 782533447342660L;

	public AuthenticatedClient(Client client) {
		super.setClientId(client.getClientId());
		super.setClientSecret(client.getClientSecret());

		super.setScope(client.getScope());
//		super.setAuthorities(client.getAuthorities().stream().map(authority -> new SimpleGrantedAuthority(authority.getName())).collect(Collectors.toCollection(HashSet::new)));
		super.setAuthorizedGrantTypes(client.getAuthorizedGrantTypes());
		super.setResourceIds(client.getResourceIds());
		super.setAccessTokenValiditySeconds(client.getAccessTokenValiditySeconds());
		super.setRefreshTokenValiditySeconds(client.getRefreshTokenValiditySeconds());
	}

}
