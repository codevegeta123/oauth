package com.exp.filter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class AccessTokenAuthenticationFilter extends OAuth2AuthenticationProcessingFilter {
	
	private String path;
	
	public AccessTokenAuthenticationFilter(String path) {
		this.path = path;
	}
	
	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
	ServletException {
		
		RequestMatcher accessPathMatcher = new AccessTokenAuthenticationMatcher(path);
		
		if(!accessPathMatcher.matches((HttpServletRequest)req)) {
			chain.doFilter(req, res);
			return;
		}
		
		super.doFilter(req, res, chain);
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
