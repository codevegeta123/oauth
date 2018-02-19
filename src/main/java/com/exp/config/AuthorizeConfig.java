package com.exp.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Order(Integer.MIN_VALUE + 10)
@Configuration
public class AuthorizeConfig extends WebSecurityConfigurerAdapter {
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			.formLogin()
			.and()
				.requestMatchers().antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access")
			.and()
				.authorizeRequests().antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access").authenticated()
			.and()
				.authorizeRequests().antMatchers("/**").permitAll();
				
	}

}
