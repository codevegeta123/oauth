OAuth2 

1. Client : 

    - OAuth2ClientContext : [OAuth2AccessToken, AccessTokenRequest]
    - Filter : 
        - OAuth2ClientAuthenticationProcessingFilter : 
              OAuth2 client filter that can be used to acquire an OAuth2 access token from an authorization server, 
              and load an authentication object into the SecurityContext
        - OAuth2ClientContextFilter :
              Security filter for an OAuth2 client.
    - resource : 
        - OAuth2ProtectedResourceDetails : 
              Details for an OAuth2-protected resource.
    - test : 
        - OAuth2ContextConfiguration : 
              Annotation to signal that an OAuth2 authentication should be created and and provided to the enclosing scope.
              Used at the class level it will apply to all test methods.
              Used at the method level it will apply only to the method, overriding any value found on the enclosing class
    - token : 
        - AccessTokenProvider : 
              A manager for an, which knows how to obtain an access token for a specific resources.
        - AccessTokenProviderChain : 
              A chain of OAuth2 access token providers. 
              This implementation will iterate through its chain to find the first provider that supports the resource 
              and use it to obtain the access token. Note that the order of the chain is relevant.
        - AccessTokenRequest : 
              Local context for an access token request encapsulating the parameters that are sent by the client requesting the token
        - ClientTokenServices : 
              Returns tokens for a mapping of resource and authenticaiton
              Impl : JdbcClientTokenServices => stores tokens in a database for retrieval by client applications.
        - ClientAuthenticationHandler : 
              Authenticate a token request. 
              Handles client authentication.
        - grant :
              - client    : ClientCredentialsAccessTokenProvider 
              - code      : AuthorizationCodeAccessTokenProvider 
              - implicit  : ImplicitAccessTokenProvider          
              - password  : ResourceOwnerPasswordAccessTokenProvider

2. Provider :
    AuthorizationRequest : Base class representing a request for authorization.
    AuthorizationRequestManager : Strategy for managing AuthorizationRequest instances during a token grant.
    ClientDetails : Client details for OAuth 2
    ClientDetailsService : A service that provides the details about an OAuth2 client.
        [JdbcClientDetailsService, InMemoryClientDetailsService]
    ClientRegistrationService : Interface for client registration, handling add, update and remove of ClientDetails from an Authorization Server.
    - code :
        JdbcAuthorizationCodeServices :  Implementation of authorization code services that stores the codes and authentication in a database
        AuthorizationCodeTokenGranter :  Token granter for the authorization code grant type.
        AuthorizationRequestHolder    :  Convenience class for AuthorizationCodeServices to store and retrieve
    - authentication :
        OAuth2AuthenticationDetails   :  A holder of selected HTTP details related to an OAuth2 authentication request
        OAuth2AuthenticationDetailsSource : A source for authentication details in an OAuth2 protected Resource
        OAuth2AuthenticationManager   : An AuthenticationManager for OAuth2 protected resources.
        OAuth2AuthenticationProcessingFilter : 
              A pre-authentication filter for OAuth2 protected resources. 
              Extracts an OAuth2 token from the in coming request and uses it to populate the Spring Security context with an OAuth2Authentication
    - approval :
        DefaultUserApprovalHandler : A default user approval handler that doesn't remember any decisions.
        TokenServicesUserApprovalHandler : A user approval handler that remembers approval decisions by consulting existing tokens
    - endpoint :
        AuthorizationEndpoint : Accepts authorization requests, and handles user approval if the grant type is authorization code.
        TokenEndpoint         : 
              Clients must be authenticated using a Spring Security Authentication to access this endpoint, 
              and the client id is extracted from the authentication token. 
              The best way to arrange this is to use HTTP basic authentication for this endpoint with standard Spring Security support.
        WhitelabelApprovalEndpoint : Controller for displaying the approval and error pages for the authorization server.
              

