package com.exp.config;

import com.exp.config.handler.CustomAccessDeniedHandler;
import com.exp.filter.AccessTokenAuthenticationFilter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

/**
 * Created by rohith on 18/2/18.
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    private DefaultTokenServices tokenServices;
	
	@Autowired
    private CustomAccessDeniedHandler customAccessDeniedHandler;
	
//	@Autowired
//	private AuthenticationManager authenticationManager;
//	
	
//	@Autowired
//	private AccessTokenAuthenticationFilter accessTokenAuthenticationFilter;
	
    
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources
            .tokenServices(tokenServices)
//            .authenticationEntryPoint(new OAuth2AuthenticationEntryPoint())
            .accessDeniedHandler(customAccessDeniedHandler);
    }

//    @Override
////    @Order(Integer.MIN_VALUE + 30)
//    public void configure(HttpSecurity http) throws Exception {
//    	
////    	http.authorizeRequests().anyRequest().permitAll();
//    	
////        http
////        	.anonymous().disable()
////            .requestMatchers().antMatchers("/user/**")
////            .and()
////            	.authorizeRequests().antMatchers("/user/**").authenticated()
////            .and()            
////				.authorizeRequests().antMatchers("/**").permitAll();
////			.and()
////				.addFilterAfter(accessTokenAuthenticationFilter("/user/profile"), LogoutFilter.class);
//    }

}
