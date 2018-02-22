package com.exp.config;

import com.exp.config.handler.CustomAccessDeniedHandler;
import com.exp.service.CustomClientDetailsService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 * Created by rohith on 18/2/18.
 */
@Configuration
@EnableResourceServer
@Order(Integer.MIN_VALUE + 50)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
	
//	@Autowired
//	private AuthenticationManager authenticationManager;
//	
	
//	@Autowired
//	private AccessTokenAuthenticationFilter accessTokenAuthenticationFilter;
	
	@Autowired
	private DefaultTokenServices tokenServices;
	
	@Autowired
    private CustomAccessDeniedHandler customAccessDeniedHandler;
	
	@Autowired
	private CustomClientDetailsService clientDetailsService;
	
//	@Autowired
//	private TokenStore tokenStore;
	
//	@Primary
//    @Bean("resourceTokenServices")
//    public DefaultTokenServices tokenServices() {
//        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
//        defaultTokenServices.setTokenStore(tokenStore);
//        defaultTokenServices.setSupportRefreshToken(true);
//        defaultTokenServices.setClientDetailsService(clientDetailsService);
//        defaultTokenServices.setAuthenticationManager(oauth2AuthenticationManager());
//        return defaultTokenServices;
//    }   
	
	@Bean("oauth2AuthenticationManager")
	public OAuth2AuthenticationManager oauth2AuthenticationManager(){
		OAuth2AuthenticationManager oauth2AuthenticationManager = new OAuth2AuthenticationManager();
		oauth2AuthenticationManager.setTokenServices(tokenServices);
		oauth2AuthenticationManager.setClientDetailsService(clientDetailsService);
		return oauth2AuthenticationManager;
	}
	
//	@Bean
//	public OAuth2AuthenticationProcessingFilter oauth2AuthenticationProcessingFilter(){
//		OAuth2AuthenticationProcessingFilter oauth2AuthenticationProcessingFilter = new OAuth2AuthenticationProcessingFilter();
//		oauth2AuthenticationProcessingFilter.setAuthenticationManager(oauth2AuthenticationManager());
//		return oauth2AuthenticationProcessingFilter;
//	}
	
	
    
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
    	
//    	http
//		.csrf().disable()
//		.requestMatchers().antMatchers("/user/**")
//		.and()
//			.authorizeRequests().antMatchers("/user/**").authenticated()
//		.and()
//			.authorizeRequests().antMatchers("/**").permitAll();
//		.and()
//			.addFilterBefore(oauth2AuthenticationProcessingFilter(), AbstractPreAuthenticatedProcessingFilter.class);
    	
    	http.authorizeRequests().anyRequest().permitAll();
    	
//        http
//        	.anonymous().disable()
//            .requestMatchers().antMatchers("/user/**")
//            .and()
//            	.authorizeRequests().antMatchers("/user/**").authenticated()
//            .and()            
//				.authorizeRequests().antMatchers("/**").permitAll();
//			.and()
//				.addFilterAfter(accessTokenAuthenticationFilter("/user/profile"), LogoutFilter.class);
    }

}
