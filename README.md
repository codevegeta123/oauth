# oauth
oauth2 server using spring security

SPRING SECURITY OAUTH2

OAUTH 2.0 Provider
	
	- Configuration involves establishing the OAuth2 clients that can access its protected resources independently/on behalf of a user. 
	- Provider does this by managing and verifying the OAuth 2.0 tokens used to access the protected resources
	- Provider must also supply an interface for the user to confirm that a client can access protected resources (i.e. confirmation page)

Provider Implementation

	- Provider role in OAuth 2.0 is actually split between Authorization Service and Resource Service

	- The requests for the tokens are handled by Spring MVC controller endpoints
	- Access to protected resources is handled by standard Spring Security request filters.

	OAuth 2.0 Authorization Server

		1. AuthorizationEndpoint is used to service requests for authorization. 
			Default URL: /oauth/authorize
		2. TokenEndpoint is used to service requests for access tokens. 
			Default URL: /oauth/token.

	Auth 2.0 Resource Server

		1. OAuth2AuthenticationProcessingFilter is used to load the Authentication for the request given an authenticated access token.

Authorization Server Configuration

	- Server, you have to consider the grant type that the client is to use to obtain an access token from the end-user

		1. Authorization code
		2. User credentials
		3. Refresh Token

	1. ClientDetailsServiceConfigurer: 
			
			- A configurer that defines the client details service, it can be initialized, or you can just refer to an existing store.
			- A callback from your AuthorizationServerConfigurer. 
			- It can be used to define an in-memory or JDBC implementation of the client details service.

				Important attributes : [client_id, secret, scope, authorities, authorizedGrantTypes]

	2. AuthorizationServerSecurityConfigurer: 

			Defines the security constraints on the token endpoint.

	3. AuthorizationServerEndpointsConfigurer: 

			Defines the authorization and token endpoints and the token services.

Managing tokens : 

	AuthorizationServerTokenServices interface defines the operations that are necessary to manage OAuth 2.0 tokens

		1. When an access token is created, the authentication must be stored.
		2. The access token is used to load the authentication that was used to authorize its creation.

	- DefaultTokenServices has many strategies that can be plugged in to change the format and storage of access tokens. 
	- By default it creates tokens via random value and handles everything except for the persistence 
	- TokenStore handles persistence of tokens.

		TokenStores : [InMemoryTokenStore, JdbcTokenStore (JwtTokenStore)]

Grant Types : 

	- Grant types supported by the AuthorizationEndpoint can be configured via the AuthorizationServerEndpointsConfigurer

	1. AuthenticationManager : 

			Password grants are switched on by injecting an AuthenticationManager.

	2. UserDetailsService :

			If you inject a UserDetailsService or if one is configured globally anyway then
				refresh token grant will contain a check on the user details, to ensure that the account is still active

	3. AuthorizationCodeServices :

			Defines the authorization code services for the auth code grant.

	4. ImplicitGrantService : 

			Manages state during the imlpicit grant

	5. TokenGranter : 

			The TokenGranter (taking full control of the granting and ignoring the other properties above).


Configuring the Endpoint URLs : 

	- AuthorizationServerEndpointsConfigurer has a pathMapping() method. It takes two arguments:

		1. The default URL path for the endpoint.
		2. The custom path required (starting with a "/").

	Default URLs provided by framework : 

		1. /oauth/authorize 		(the authorization endpoint) 
		2. /oauth/token 			(the token endpoint)
		3. /oauth/confirm_access 	(user posts approval for grants here)
		4. /oauth/error 			(used to render errors in the authorization server)
		5. /oauth/check_token 		(used by Resource Servers to decode access tokens)
		6. /oauth/token_key 		(exposes public key for token verification if using JWT tokens).

	- /oauth/authorize should be protected using Spring Security so that it is only accessible to authenticated users.

	- If your authorization server is also resource server, then 

		1. There is another security filter chain with lower priority controlling the API resources.
		2. Be sure to include a request matcher that picks out only non-API resources in the WebSecurityConfigurer.
		
	- Token endpoint is protected by default, the @Configuration support using HTTP Basic authentication of the client secret. 

Customizing UI : 

	- 





Mapping user roles to scopes :

	- Limit the scope of tokens not only by the scopes assigned to the client, but also according to the user's own permissions.
	- DefaultOAuth2RequestFactory in your AuthorizationEndpoint, flag checkUserScopes=true to restrict permitted scopes to only those that match the user's roles.
	- Inject an OAuth2RequestFactory into the TokenEndpoint but that only works (i.e. with password grants) if you also install a TokenEndpointAuthenticationFilter, you just need to add that filter after the HTTP BasicAuthenticationFilter
	- AuthorizationServerEndpointsConfigurer allows you to inject a custom OAuth2RequestFactory


Resource Server Configuration :

	- A Resource Server serves resources that are protected by the OAuth2 token.
	- Spring Security authentication filter that this protection.

	Configurations : 

		1. TokenServices : 

				The bean that defines the token services (instance of ResourceServerTokenServices)

		2. resource_id :

				id for the resource (optional, but recommended and will be validated by the auth server if present)

		3. Others : 

			- Request matchers for protected resources (defaults to all)
			- Access rules for protected resources (defaults to plain "authenticated")
			- Customizations for the protected resources permitted by the HttpSecurity configurer.
