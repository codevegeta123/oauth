package com.exp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import com.exp.filter.AccessTokenAuthenticationFilter;
import com.exp.service.CustomClientDetailsService;

@Configuration
@Order(Integer.MIN_VALUE + 50)
public class AccessTokenConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private DefaultTokenServices tokenServices;
	
	@Autowired
	private CustomClientDetailsService clientDetailsService;
	
	@Autowired
	@Qualifier("oauth2AuthenticationManager")
	private OAuth2AuthenticationManager oauth2AuthenticationManager;
	
//	@Bean("oauth2AuthenticationManager")
//	public OAuth2AuthenticationManager oauth2AuthenticationManager(){
//		OAuth2AuthenticationManager oauth2AuthenticationManager = new OAuth2AuthenticationManager();
//		oauth2AuthenticationManager.setTokenServices(tokenServices);
//		oauth2AuthenticationManager.setClientDetailsService(clientDetailsService);
//		return oauth2AuthenticationManager;
//	}
	
//	@Bean
//	public OAuth2AuthenticationProcessingFilter oauth2AuthenticationProcessingFilter(){
//		OAuth2AuthenticationProcessingFilter oauth2AuthenticationProcessingFilter = new OAuth2AuthenticationProcessingFilter();
//		oauth2AuthenticationProcessingFilter.setAuthenticationManager(oauth2AuthenticationManager);
////		oauth2AuthenticationProcessingFilter.setStateless(false);
//		return oauth2AuthenticationProcessingFilter;
//	}
	
	@Bean
	@Value("/user/profile")
	public AccessTokenAuthenticationFilter accessTokenAuthenticationFilter(String path) {
		AccessTokenAuthenticationFilter accessTokenAuthenticationFilter = new AccessTokenAuthenticationFilter(path);
		accessTokenAuthenticationFilter.setAuthenticationManager(oauth2AuthenticationManager);
		return accessTokenAuthenticationFilter;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
//		OAuth2AuthenticationProcessingFilter oauth2AuthenticationProcessingFilter = oauth2AuthenticationProcessingFilter();
//		oauth2AuthenticationProcessingFilter.setStateless(true);
		
		http
			.csrf().disable()
			.requestMatchers().antMatchers("/user/**")
			.and()
				.addFilterBefore(accessTokenAuthenticationFilter("/user/**"), AbstractPreAuthenticatedProcessingFilter.class)
				.authorizeRequests().antMatchers("/user/**").authenticated()
			.and()
				.authorizeRequests().antMatchers("/**").permitAll();
	    
	}

}
