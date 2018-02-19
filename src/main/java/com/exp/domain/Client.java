package com.exp.domain;

import org.springframework.security.core.GrantedAuthority;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Transient;

import java.io.Serializable;
import java.util.*;

/**
 * Created by rohith on 19/2/18.
 */
@Entity
@Table(name = "oauth_client_details")
public class Client implements Serializable {

    private static final long serialVersionUID = -3218173333657412026L;

    @Id
    @Column(name = "client_id")
    private String clientId;

    @Column(name = "resource_ids")
    private String resourceIds;
    
    @Transient
    private boolean secretRequired = true;

    @Column(name = "client_secret")
    private String clientSecret;
    
    @Transient
    private boolean scoped = true;

    @Column(name = "scope")
    public String scope;

    @Column(name = "authorized_grant_types")
    public String authorizedGrantTypes;

    @Column(name = "web_server_redirect_uri")
    public String registeredRedirectUri;

    @Column(name = "authorities")
    public String authorities;

    @Column(name = "access_token_validity")
    public Integer accessTokenValiditySeconds;

    @Column(name = "refresh_token_validity")
    public Integer refreshTokenValiditySeconds;

    @Column(name = "additional_information")
    public String additionalInformation;

    public static long getSerialVersionUID() {
        return serialVersionUID;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public Set getResultantSet(String str) {
        return (str == null) ? Collections.emptySet() : Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(str.split(","))));
    }

    public String setResultantString(Set<String> set) {
        return (set == null) ? null : String.join(",", set);
    }

    public Set<String> getResourceIds() {
        return getResultantSet(resourceIds);
    }

    public void setResourceIds(Set<String> resourceIds) {
        this.resourceIds = setResultantString(resourceIds);
    }

    public boolean isSecretRequired() {
        return secretRequired;
    }

    public void setSecretRequired(boolean secretRequired) {
        this.secretRequired = secretRequired;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public boolean isScoped() {
        return scoped;
    }

    public void setScoped(boolean scoped) {
        this.scoped = scoped;
    }

    public Set<String> getScope() {
        return getResultantSet(scope);
    }

    public void setScope(Set<String> scope) {
        this.scope = setResultantString(scope);
    }

    public Set<String> getAuthorizedGrantTypes() {
        return getResultantSet(authorizedGrantTypes);
    }

    public void setAuthorizedGrantTypes(Set<String> authorizedGrantTypes) {
        this.authorizedGrantTypes = setResultantString(authorizedGrantTypes);
    }

    public Set<String> getRegisteredRedirectUri() {
        return getResultantSet(registeredRedirectUri);
    }

    public void setRegisteredRedirectUri(Set<String> registeredRedirectUri) {
        this.registeredRedirectUri = setResultantString(registeredRedirectUri);
    }

    public Integer getAccessTokenValiditySeconds() {
        return accessTokenValiditySeconds;
    }

    public void setAccessTokenValiditySeconds(Integer accessTokenValiditySeconds) {
        this.accessTokenValiditySeconds = accessTokenValiditySeconds;
    }

    public Integer getRefreshTokenValiditySeconds() {
        return refreshTokenValiditySeconds;
    }

    public void setRefreshTokenValiditySeconds(Integer refreshTokenValiditySeconds) {
        this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
    }


}
