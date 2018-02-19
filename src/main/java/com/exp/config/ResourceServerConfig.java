package com.exp.config;

import com.exp.config.handler.CustomAccessDeniedHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

/**
 * Created by rohith on 18/2/18.
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    private CustomAccessDeniedHandler customAccessDeniedHandler;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.
            anonymous().disable()
            .requestMatchers().antMatchers("/api/**")
            .and().authorizeRequests()
            .antMatchers("/api/**").access("hasRole('ADMIN') or hasRole('USER')")
            .and().exceptionHandling().accessDeniedHandler(customAccessDeniedHandler);
    }

}
