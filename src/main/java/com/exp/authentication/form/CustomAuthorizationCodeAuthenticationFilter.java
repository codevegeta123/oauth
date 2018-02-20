package com.exp.authentication.form;

import com.exp.repository.AuthCodeRepository;
import com.exp.service.CustomUserDetailsService;

import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Created by rohith on 17/2/18.
 */
public class CustomAuthorizationCodeAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final String CHARACTER_ENCODING_UTF_8 = "UTF-8";

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private AuthCodeRepository authCodeRepository;

    public CustomAuthorizationCodeAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher, CustomUserDetailsService userDetailsService) {
        super(requiresAuthenticationRequestMatcher);
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
    	
//    	String username = request.getParameter("username");
//        String password = request.getParameter("password");
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("peddirohith", "next123");
        
    	
        String username = request.getParameter("username");
        String password = request.getParameter("password");
//        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        return this.getAuthenticationManager().authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authentication) throws IOException, ServletException {
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(CHARACTER_ENCODING_UTF_8);

        JSONObject jsonResponse = new JSONObject();

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
            throws IOException, ServletException {
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(CHARACTER_ENCODING_UTF_8);
        JSONObject jsonResponse = new JSONObject();
        try {
			jsonResponse.put("message", "Invalid Credentials");
		} catch (JSONException e) {
			e.printStackTrace();
		}
        response.getWriter().write(jsonResponse.toString());
    }
}
