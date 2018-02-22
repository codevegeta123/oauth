package com.exp.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
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

//		final boolean debug = logger.isDebugEnabled();
//		final HttpServletRequest request = (HttpServletRequest) req;
//		final HttpServletResponse response = (HttpServletResponse) res;
//		
//		try {
//		
//			Authentication authentication = tokenExtractor.extract(request);
//			
//			if (authentication == null) {
//				if (stateless && isAuthenticated()) {
//					if (debug) {
//						logger.debug("Clearing security context.");
//					}
//					SecurityContextHolder.clearContext();
//				}
//				if (debug) {
//					logger.debug("No token in request, will continue chain.");
//				}
//			}
//			else {
//				request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, authentication.getPrincipal());
//				if (authentication instanceof AbstractAuthenticationToken) {
//					AbstractAuthenticationToken needsDetails = (AbstractAuthenticationToken) authentication;
//					needsDetails.setDetails(authenticationDetailsSource.buildDetails(request));
//				}
//				Authentication authResult = authenticationManager.authenticate(authentication);
//		
//				if (debug) {
//					logger.debug("Authentication success: " + authResult);
//				}
//		
//				eventPublisher.publishAuthenticationSuccess(authResult);
//				SecurityContextHolder.getContext().setAuthentication(authResult);
//		
//			}
//		}
//		catch (OAuth2Exception failed) {
//			SecurityContextHolder.clearContext();
//		
//			if (debug) {
//				logger.debug("Authentication request failed: " + failed);
//			}
//			eventPublisher.publishAuthenticationFailure(new BadCredentialsException(failed.getMessage(), failed),
//					new PreAuthenticatedAuthenticationToken("access-token", "N/A"));
//		
//			authenticationEntryPoint.commence(request, response,
//					new InsufficientAuthenticationException(failed.getMessage(), failed));
//		
//			return;
//		}
//		
//		chain.doFilter(request, response);
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
