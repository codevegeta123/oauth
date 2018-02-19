package com.exp.config;

import com.exp.authentication.form.CustomFormAuthenticationFilter;
import com.exp.authentication.form.FormAuthenticationProvider;
import com.exp.config.handler.CustomAccessDeniedHandler;
import com.exp.config.handler.CustomAuthenticationEntryPoint;
import com.exp.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import javax.sql.DataSource;

/**
 * Created by rohith on 17/2/18.
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    @Qualifier("primaryOauthDataSource")
    private DataSource dataSource;

//    @Autowired
//    private CustomAccessDeniedHandler customAccessDeniedHandler;
//
//    @Autowired
//    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private ClientDetailsService clientDetailsService;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private FormAuthenticationProvider formAuthenticationProvider;

    protected CustomFormAuthenticationFilter getCustomAuthenticationFilter(String pattern)throws Exception{
        CustomFormAuthenticationFilter customAuthenticationFilter =
                new CustomFormAuthenticationFilter(new AntPathRequestMatcher(pattern), userDetailsService);
        customAuthenticationFilter.setAuthenticationManager(authenticationManagerBean());
        return customAuthenticationFilter;
    }

    @Override
//    @Order(-5)
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    protected void configure(HttpSecurity http) throws Exception {
    	
//    	http
//    		.csrf().disable()
//    		.formLogin().loginPage("/login").permitAll()
//    		.and()
//    			.requestMatchers()
//    			.antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access")
//			.and()
//				.authorizeRequests().anyRequest().authenticated()
//			.and()
//				.userDetailsService(userDetailsService);
    	
//    	http
//    		.csrf().disable()
//			.authorizeRequests()
//			.antMatchers("/oauth/token**")
//			.authenticated()
//			.and()
//				.addFilterBefore(getCustomAuthenticationFilter("/oauth/token"), BasicAuthenticationFilter.class)
//				.authenticationProvider(formAuthenticationProvider);
//    	
//    	http
//    		.csrf().disable()
//    		.authorizeRequests()
//    		.antMatchers("/login").permitAll()
//    		.anyRequest().authenticated()
//    		.and().formLogin().permitAll();   	
    	

//        http
//                .csrf().disable()
//                .authorizeRequests()
//                .antMatchers("/login").permitAll()
//                .antMatchers("/oauth/token/revokeById/**").permitAll()
//                .antMatchers("/tokens/**").permitAll()
//                .antMatchers("/oauth/token**").permitAll()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin().permitAll();
//                .and()
//                .addFilterBefore(getCustomOauthAuthenticationFilter("/oauth/token**"), BasicAuthenticationFilter.class);

        // @formatter:off
//        http
//            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//            .and()
//            .csrf().disable()
//            .formLogin()
//                .loginProcessingUrl("/auth/login")
//            .and()
//                .logout()
//                .deleteCookies("JSESSIONID")
//                .logoutUrl("/auth/logout")
//            .and()
//                .authorizeRequests()
//                .antMatchers("/auth/login").permitAll()
//            .and()
//                .authorizeRequests()
//                .antMatchers("/secure/admin").access("hasRole('ADMIN')")//.access("hasAuthority('ROLE_ADMIN')")
//                .anyRequest().authenticated()
//            .and()
//                .exceptionHandling().accessDeniedHandler(customAccessDeniedHandler)
//                .authenticationEntryPoint(customAuthenticationEntryPoint)
//            .and()
//                .addFilterBefore(getCustomAuthenticationFilter("/auth/login"), UsernamePasswordAuthenticationFilter.class)
//            .anonymous()
//                .disable();
        // @formatter:on
    }

//    @Override
//    @Order(Ordered.HIGHEST_PRECEDENCE)
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//            .and()
//            .csrf().disable()
//            .authorizeRequests()
//            .antMatchers("/login").permitAll()
//            .antMatchers("/oauth/token").permitAll()
//            //.antMatchers("/api/**").authenticated()
//            .anyRequest().authenticated()
//            .and()
//            .httpBasic()
//            .realmName("CRM_REALM");
//    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
        	.parentAuthenticationManager(authenticationManager)
//        	.authenticationProvider(formAuthenticationProvider)
            .userDetailsService(userDetailsService)
            .and()
            .jdbcAuthentication().dataSource(dataSource);
    }

//    @Override
//    @Bean
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        return super.authenticationManagerBean();
//    }

//    @Bean
//    @Autowired
//    public TokenStoreUserApprovalHandler userApprovalHandler(TokenStore tokenStore){
//        TokenStoreUserApprovalHandler handler = new TokenStoreUserApprovalHandler();
//        handler.setTokenStore(tokenStore);
//        handler.setRequestFactory(new DefaultOAuth2RequestFactory(clientDetailsService));
//        handler.setClientDetailsService(clientDetailsService);
//        return handler;
//    }

    @Bean
    @Autowired
    public ApprovalStore approvalStore(TokenStore tokenStore) throws Exception {
        TokenApprovalStore store = new TokenApprovalStore();
        store.setTokenStore(tokenStore);
        return store;
    }

    /******************************************************************************************************/

//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//            .addFilterBefore(remoteUserAuthenticationFilter(), RequestHeaderAuthenticationFilter.class)
//            .authenticationProvider(preauthAuthProvider())
//            .authorizeRequests().anyRequest().authenticated();
//    }
//
//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(preauthAuthProvider());
//    }
//
//    @Bean
//    public UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> userDetailsServiceWrapper() {
//        UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> wrapper =
//                new UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken>();
//        wrapper.setUserDetailsService(new RemoteUserDetailsService());
//        return wrapper;
//    }
//
//    @Bean
//    public PreAuthenticatedAuthenticationProvider preauthAuthProvider() {
//        PreAuthenticatedAuthenticationProvider preauthAuthProvider =
//                new PreAuthenticatedAuthenticationProvider();
//        preauthAuthProvider.setPreAuthenticatedUserDetailsService(userDetailsServiceWrapper());
//        return preauthAuthProvider;
//    }
//
//    @Bean
//    public RemoteUserAuthenticationFilter remoteUserAuthenticationFilter() throws Exception {
//        RemoteUserAuthenticationFilter filter = new RemoteUserAuthenticationFilter();
//        filter.setAuthenticationManager(authenticationManager());
//        return filter;
//    }


}
