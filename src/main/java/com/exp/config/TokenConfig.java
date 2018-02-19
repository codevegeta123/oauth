package com.exp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.exp.authentication.form.CustomFormAuthenticationFilter;
import com.exp.service.CustomUserDetailsService;

@Order(Integer.MIN_VALUE + 20)
@Configuration
public class TokenConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private CustomUserDetailsService userDetailsService;
	
	protected CustomFormAuthenticationFilter getCustomAuthenticationFilter(String pattern)throws Exception{
        CustomFormAuthenticationFilter customAuthenticationFilter =
                new CustomFormAuthenticationFilter(new AntPathRequestMatcher(pattern), userDetailsService);
        customAuthenticationFilter.setAuthenticationManager(authenticationManagerBean());
        return customAuthenticationFilter;
    }
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http
			.csrf().disable()
			.authorizeRequests().antMatchers("/oauth/token**").authenticated()
			.and()
				.authorizeRequests().antMatchers("/**").permitAll()
			.and()
				.addFilterBefore(getCustomAuthenticationFilter("/oauth/token**"), BasicAuthenticationFilter.class);
				
		
//		http
//		.csrf().disable()
//		.addFilterBefore(getCustomAuthenticationFilter("/oauth/token**"), BasicAuthenticationFilter.class)
//		.and()
//			.authorizeRequests().antMatchers( "/oauth/token**")
//			.authenticated()
//		.and()
//			.authorizeRequests().antMatchers("/**").permitAll();
	}

}