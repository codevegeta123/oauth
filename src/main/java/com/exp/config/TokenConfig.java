package com.exp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Order(Integer.MIN_VALUE + 20)
@Configuration
public class TokenConfig extends WebSecurityConfigurerAdapter {
	
	
	@Autowired
	@Qualifier("clientAndUserAuthenticationManager")
	private AuthenticationManager authenticationManager;
	
	@Bean
	public ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter() {
		ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter= new ClientCredentialsTokenEndpointFilter();
		clientCredentialsTokenEndpointFilter.setAuthenticationManager(authenticationManager);
		return clientCredentialsTokenEndpointFilter;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http
			.csrf().disable()
			.requestMatchers().antMatchers("/oauth/token")
			.and()
				.authorizeRequests().antMatchers("/oauth/token").authenticated()
			.and()
				.authorizeRequests().antMatchers("/**").permitAll()
			.and()
				.addFilterBefore(clientCredentialsTokenEndpointFilter(), UsernamePasswordAuthenticationFilter.class);
	}

}
