package com.exp.filter;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class AccessTokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	
	@Autowired
	private DefaultTokenServices tokenServices;
	
//	public AccessTokenAuthenticationFilter() {
//		this("/user/profile");
//	}

	public AccessTokenAuthenticationFilter(String path) {
		super(path);
		setRequiresAuthenticationRequestMatcher(new AccessTokenAuthenticationMatcher(path));
	}
	
	public AccessTokenAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
		super(requiresAuthenticationRequestMatcher);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		
		String accessTokenValue = request.getHeader("Authorization").substring("Bearer".length()+1);
		OAuth2Authentication authentication = tokenServices.loadAuthentication(accessTokenValue);				
		return authentication;
	}
	
	
	protected static class AccessTokenAuthenticationMatcher implements RequestMatcher {

		private String path;

		public AccessTokenAuthenticationMatcher(String path) {
			this.path = path;

		}

		@Override
		public boolean matches(HttpServletRequest request) {
			String uri = request.getRequestURI();
			int pathParamIndex = uri.indexOf(';');

			if (pathParamIndex > 0) {
				// strip everything after the first semi-colon
				uri = uri.substring(0, pathParamIndex);
			}

			if ("".equals(request.getContextPath())) {
				return uri.endsWith(path);
			}

			return uri.endsWith(request.getContextPath() + path);
		}

	}
	

}
