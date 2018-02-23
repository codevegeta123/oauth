package com.exp.config;

import com.exp.config.handler.CustomAccessDeniedHandler;
import com.exp.service.CustomClientDetailsService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;

/**
 * Created by rohith on 18/2/18.
 */
@Configuration
@EnableResourceServer
@Order(Integer.MIN_VALUE + 50)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
	
	
	@Autowired
	private DefaultTokenServices tokenServices;
	
	@Autowired
    private CustomAccessDeniedHandler customAccessDeniedHandler;
	
	@Autowired
	private CustomClientDetailsService clientDetailsService;
	
	@Bean("oauth2AuthenticationManager")
	public OAuth2AuthenticationManager oauth2AuthenticationManager(){
		OAuth2AuthenticationManager oauth2AuthenticationManager = new OAuth2AuthenticationManager();
		oauth2AuthenticationManager.setTokenServices(tokenServices);
		oauth2AuthenticationManager.setClientDetailsService(clientDetailsService);
		return oauth2AuthenticationManager;
	}
    
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources
            .tokenServices(tokenServices)
            .authenticationManager(oauth2AuthenticationManager())
            .authenticationEntryPoint(new OAuth2AuthenticationEntryPoint())
            .accessDeniedHandler(customAccessDeniedHandler);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
    	
    	http.authorizeRequests().anyRequest().permitAll();
    }

}
