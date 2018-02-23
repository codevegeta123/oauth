package com.exp.config;

import com.exp.service.CustomClientDetailsService;
import com.exp.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import java.util.Arrays;

import javax.sql.DataSource;

/**
 * Created by rohith on 18/2/18.
 */
@EnableAuthorizationServer
@Configuration
public class AuthServerOAuth2Config extends AuthorizationServerConfigurerAdapter {

    @Autowired
    @Qualifier("primaryOauthDataSource")
    private DataSource dataSource;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;
    
    @Autowired
    private CustomClientDetailsService customClientDetailsService;    
    
    @Bean
    public TokenStore tokenStore() {
        return new JdbcTokenStore(dataSource);
    }

    @Bean
    public AuthorizationCodeServices authorizationCodeServices() {
        return new JdbcAuthorizationCodeServices(dataSource);
    }
    
    @Bean
    public OAuth2RequestFactory requestFactory() {
    	return new DefaultOAuth2RequestFactory(customClientDetailsService);
    }

    @Primary
    @Bean
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setSupportRefreshToken(true);
        defaultTokenServices.setClientDetailsService(customClientDetailsService);
        defaultTokenServices.setAuthenticationManager(authenticationManager());
        return defaultTokenServices;
    }   
    
    @Bean
    public  AuthorizationCodeTokenGranter authorizationTokenGranter() throws Exception {
        return new AuthorizationCodeTokenGranter(tokenServices(), authorizationCodeServices(), customClientDetailsService, requestFactory());
    }
    
    @Bean(name = "clientAuthenticationProvider")
	public AuthenticationProvider clientAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(new ClientDetailsUserDetailsService(customClientDetailsService));
		return provider;
	}
    
    @Bean(name = "userAuthenticationProvider")
	public AuthenticationProvider userAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(customUserDetailsService);
		return provider;
	}
    
    @Bean("clientAndUserAuthenticationManager")
	public AuthenticationManager authenticationManager() {
		return new ProviderManager(Arrays.asList(clientAuthenticationProvider(), userAuthenticationProvider()));
	}

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//        security.realm()
//        security.checkTokenAccess("permitAll()");
    }    

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//        clients.jdbc(dataSource);
    	clients.withClientDetails(customClientDetailsService).build();
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .tokenStore(tokenStore())
                .authorizationCodeServices(authorizationCodeServices())
                .tokenGranter(authorizationTokenGranter())
//                .userApprovalHandler(userApprovalHandler)
                .authenticationManager(authenticationManager())
                .userDetailsService(customUserDetailsService);
    }
}