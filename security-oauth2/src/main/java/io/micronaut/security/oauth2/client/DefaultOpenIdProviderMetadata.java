/*
 * Copyright 2017-2023 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.oauth2.client;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.annotation.ReflectiveAccess;
import io.micronaut.serde.annotation.Serdeable;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID connect Discovery Spec</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@ReflectiveAccess
@Serdeable
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class DefaultOpenIdProviderMetadata implements OpenIdProviderMetadata {

    private String providerName;
    private String authorizationEndpoint;
    private List<String> idTokenSigningAlgValuesSupported;
    private String issuer;
    private String jwksUri;
    private List<String> acrValuesSupported;
    private List<String> responseTypesSupported;
    private List<String> responseModesSupported;
    private List<String> scopesSupported;
    private List<String> grantTypesSupported;
    private List<String> subjectTypesSupported;
    private String tokenEndpoint;
    private List<String> tokenEndpointAuthMethodsSupported;
    private String userinfoEndpoint;
    private String registrationEndpoint;
    private List<String> claimsSupported;
    private List<String> codeChallengeMethodsSupported;
    private String introspectionEndpoint;
    private List<String> introspectionEndpointAuthMethodsSupported;
    private String revocationEndpoint;
    private List<String> revocationEndpointAuthMethodsSupported;
    private String endSessionEndpoint;
    private Boolean requestParameterSupported;
    private Boolean requestUriParameterSupported;
    private Boolean requireRequestUriRegistration;
    private List<String> requestObjectSigningAlgValuesSupported;
    private String serviceDocumentation;
    private List<String> idTokenEncryptionEncValuesSupported;
    private List<String> displayValuesSupported;
    private List<String> claimTypesSupported;
    private Boolean claimsParameterSupported = Boolean.FALSE;
    private String opTosUri;
    private String opPolicyUri;
    private List<String> uriLocalesSupported;
    private List<String> claimsLocalesSupported;
    private List<String> userinfoEncryptionAlgValuesSupported;
    private List<String> userinfoEncryptionEncValuesSupported;
    private List<String> tokenEndpointAuthSigningAlgValuesSupported;
    private List<String> requestObjectEncryptionAlgValuesSupported;
    private List<String> requestObjectEncryptionEncValuesSupported;
    private String checkSessionIframe;

    /**
     * @deprecated Use {@link DefaultOpenIdProviderMetadata(String)} instead.
     */
    @Deprecated(forRemoval = true, since = "4.5.0")
    public DefaultOpenIdProviderMetadata() {
        this.providerName = "";
    }

    /**
     *
     * @param providerName Provider Name
     */
    public DefaultOpenIdProviderMetadata(@NonNull String providerName) {
        this.providerName = providerName;
    }

    @Override
    @NonNull
    @JsonIgnore
    /**
     *
     * @return The configured provider name
     */
    public String getName() {
        return this.providerName;
    }

    /**
     *
     * @param name The configured provider name
     */
    public void setName(@NonNull String name) {
        this.providerName = name;
    }

    /**
     *
     * @return Boolean value specifying whether the OP requires any request_uri values used to be pre-registered using the request_uris registration parameter.
     */
    @Nullable
    public Boolean getRequireRequestUriRegistration() {
        return requireRequestUriRegistration;
    }

    /**
     *
     * @return If require_request_uri_registration omitted, the default value is false.
     */
    @Nullable
    public Boolean getDefaultRequireRequestUriRegistration() {
        return Boolean.FALSE;
    }

    /**
     *
     * @param requireRequestUriRegistration Boolean value specifying whether the OP requires any request_uri values used to be pre-registered using the request_uris registration parameter.
     */
    public void setRequireRequestUriRegistration(@Nullable Boolean requireRequestUriRegistration) {
        this.requireRequestUriRegistration = requireRequestUriRegistration;
    }

    @NonNull
    @Override
    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    /**
     *
     * @param authorizationEndpoint URL of the Open ID Provider's OAuth 2.0 Authorization Endpoint.
     */
    public void setAuthorizationEndpoint(@NonNull String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    /**
     *
     * @param userinfoEncryptionEncValuesSupported List of the JWE encryption algorithms (enc values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT.
     */
    public void setUserinfoEncryptionEncValuesSupported(@Nullable List<String> userinfoEncryptionEncValuesSupported) {
        this.userinfoEncryptionEncValuesSupported = userinfoEncryptionEncValuesSupported;
    }

    @NonNull
    @Override
    public List<String> getIdTokenSigningAlgValuesSupported() {
        return idTokenSigningAlgValuesSupported;
    }

    @Nullable
    @Override
    public List<String> getIdTokenEncryptionEncValuesSupported() {
        return idTokenEncryptionEncValuesSupported;
    }

    /**
     *
     * @param idTokenEncryptionEncValuesSupported List of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT.
     */
    public void setIdTokenEncryptionEncValuesSupported(@Nullable List<String> idTokenEncryptionEncValuesSupported) {
        this.idTokenEncryptionEncValuesSupported = idTokenEncryptionEncValuesSupported;
    }

    @Override
    public List<String> getUserinfoEncryptionAlgValuesSupported() {
        return userinfoEncryptionAlgValuesSupported;
    }

    /**
     *
     * @param userinfoEncryptionAlgValuesSupported List of the JWE [JWE] encryption algorithms (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT.
     */
    public void setUserinfoEncryptionAlgValuesSupported(@Nullable List<String> userinfoEncryptionAlgValuesSupported) {
        this.userinfoEncryptionAlgValuesSupported = userinfoEncryptionAlgValuesSupported;
    }

    @Nullable
    @Override
    public List<String> getUserinfoEncryptionEncValuesSupported() {
        return userinfoEncryptionEncValuesSupported;
    }

    /**
     *
     * @param idTokenSigningAlgValuesSupported List of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT.
     */
    public void setIdTokenSigningAlgValuesSupported(@NonNull List<String> idTokenSigningAlgValuesSupported) {
        this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
    }

    @NonNull
    @Override
    public String getIssuer() {
        return issuer;
    }

    /**
     *
     * @param issuer URL using the https scheme with no query or fragment component that the Open ID Provider asserts as its Issuer Identifier.
     */
    public void setIssuer(@NonNull String issuer) {
        this.issuer = issuer;
    }

    @NonNull
    @Override
    public String getJwksUri() {
        return jwksUri;
    }

    /**
     *
     * @param jwksUri URL of the Open ID Provider's JSON Web Key Set.
     */
    public void setJwksUri(@NonNull String jwksUri) {
        this.jwksUri = jwksUri;
    }

    /**
     * As specified in Open ID Discovery Spec, if omitted, the
     * default for Dynamic OpenID Providers is ["query", "fragment"].
     * @return Supported response types.
     */
    @Nullable
    @Override
    public List<String> getResponseTypesSupported() {
        return responseTypesSupported;
    }

    /**
     *
     * @return if Response Types Supported is ommited, default for Dynamic OpenID Providers is ["query", "fragment"].
     */
    @NonNull
    public List<String> getDefaultResponseTypesSupported() {
        return Arrays.asList("query", "fragment");
    }

    /**
     *
     * @param responseTypesSupported List of the OAuth 2.0 response_type values that this Open ID Provider supports.
     */
    public void setResponseTypesSupported(@Nullable List<String> responseTypesSupported) {
        this.responseTypesSupported = responseTypesSupported;
    }

    @Nullable
    @Override
    public List<String> getScopesSupported() {
        return scopesSupported;
    }

    /**
     *
     * @param scopesSupported List of the OAuth 2.0 [RFC6749] scope values that this server supports.
     */
    public void setScopesSupported(@Nullable List<String> scopesSupported) {
        this.scopesSupported = scopesSupported;
    }

    @NonNull
    @Override
    public List<String> getSubjectTypesSupported() {
        return subjectTypesSupported;
    }

    /**
     *
     * @param subjectTypesSupported List of the Subject Identifier types that this OP supports.
     */
    public void setSubjectTypesSupported(@NonNull List<String> subjectTypesSupported) {
        this.subjectTypesSupported = subjectTypesSupported;
    }

    @NonNull
    @Override
    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    /**
     *
     * @param tokenEndpoint URL of the Open ID Provider's OAuth 2.0 Token Endpoint.
     */
    public void setTokenEndpoint(@Nullable String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    @Nullable
    @Override
    public List<String> getTokenEndpointAuthMethodsSupported() {
        return tokenEndpointAuthMethodsSupported;
    }

    @Nullable
    @Override
    public List<String> getTokenEndpointAuthSigningAlgValuesSupported() {
        return tokenEndpointAuthSigningAlgValuesSupported;
    }

    /**
     *
     * @param tokenEndpointAuthSigningAlgValuesSupported List of the JWS signing algorithms (alg values) supported by the Token Endpoint.
     */
    public void setTokenEndpointAuthSigningAlgValuesSupported(@Nullable List<String> tokenEndpointAuthSigningAlgValuesSupported) {
        this.tokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported;
    }

    @Nullable
    @Override
    public List<String> getDisplayValuesSupported() {
        return displayValuesSupported;
    }

    /**
     *
     * @param displayValuesSupported List of the display parameter values that the OpenID Provider supports.
     */
    public void setDisplayValuesSupported(@Nullable List<String> displayValuesSupported) {
        this.displayValuesSupported = displayValuesSupported;
    }

    @Nullable
    @Override
    public List<String> getClaimTypesSupported() {
        return claimTypesSupported;
    }

    /**
     *
     * @param claimTypesSupported List of the Claim Types that the OpenID Provider supports.
     */
    public void setClaimTypesSupported(@Nullable List<String> claimTypesSupported) {
        this.claimTypesSupported = claimTypesSupported;
    }

    /**
     *
     * @param tokenEndpointAuthMethodsSupported List of Client Authentication methods supported by this Token Endpoint.
     */
    public void setTokenEndpointAuthMethodsSupported(@Nullable List<String> tokenEndpointAuthMethodsSupported) {
        this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
    }

    @Nullable
    @Override
    public String getUserinfoEndpoint() {
        return userinfoEndpoint;
    }

    /**
     *
     * @param userinfoEndpoint URL of the Open ID Provider's UserInfo Endpoint.
     */
    public void setUserinfoEndpoint(@Nullable String userinfoEndpoint) {
        this.userinfoEndpoint = userinfoEndpoint;
    }

    @Nullable
    @Override
    public List<String> getResponseModesSupported() {
        return responseModesSupported;
    }

    /**
     *
     * @param responseModesSupported List of the OAuth 2.0 response_mode values that this Open ID Provider supports.
     */
    public void setResponseModesSupported(@Nullable List<String> responseModesSupported) {
        this.responseModesSupported = responseModesSupported;
    }

    @Nullable
    @Override
    public List<String> getGrantTypesSupported() {
        return grantTypesSupported;
    }

    /**
     * As specified in Open ID Discovery Spec, if omitted,
     * the default value is ["authorization_code", "implicit"].
     * @return Default Grant Types if grantTypesSupported is ommited.
     */
    @NonNull
    public List<String> getDefaultGrantTypesSupported() {
        return Arrays.asList("authorization_code", "implicit");
    }

    @Nullable
    @Override
    public List<String> getAcrValuesSupported() {
        return acrValuesSupported;
    }

    /**
     *
     * @param acrValuesSupported List of the Authentication Context Class References that this OP supports.
     */
    public void setAcrValuesSupported(@Nullable List<String> acrValuesSupported) {
        this.acrValuesSupported = acrValuesSupported;
    }

    /**
     *
     * @param grantTypesSupported List of the OAuth 2.0 Grant Type values that this Open ID Provider supports.
     */
    public void setGrantTypesSupported(@Nullable List<String> grantTypesSupported) {
        this.grantTypesSupported = grantTypesSupported;
    }

    @Nullable
    @Override
    public String getRegistrationEndpoint() {
        return registrationEndpoint;
    }

    /**
     *
     * @param registrationEndpoint URL of the Open ID Provider's Dynamic Client Registration Endpoint.
     */
    public void setRegistrationEndpoint(@Nullable String registrationEndpoint) {
        this.registrationEndpoint = registrationEndpoint;
    }

    @Nullable
    @Override
    public List<String> getClaimsSupported() {
        return claimsSupported;
    }

    @Nullable
    @Override
    public String getServiceDocumentation() {
        return serviceDocumentation;
    }

    /**
     *
     * @param serviceDocumentation URL of a page containing human-readable information that developers might want or need to know when using the OpenID Provider.
     */
    public void setServiceDocumentation(@Nullable String serviceDocumentation) {
        this.serviceDocumentation = serviceDocumentation;
    }

    @Nullable
    @Override
    public List<String> getClaimsLocalesSupported() {
        return claimsLocalesSupported;
    }

    /**
     *
     * @param claimsLocalesSupported Languages and scripts supported for values in Claims.
     */
    public void setClaimsLocalesSupported(@Nullable List<String> claimsLocalesSupported) {
        this.claimsLocalesSupported = claimsLocalesSupported;
    }

    @Nullable
    @Override
    public List<String> getUriLocalesSupported() {
        return uriLocalesSupported;
    }

    /**
     *
     * @param uriLocalesSupported Languages and scripts supported for the user interface.
     */
    public void setUriLocalesSupported(@Nullable List<String> uriLocalesSupported) {
        this.uriLocalesSupported = uriLocalesSupported;
    }

    @Nullable
    @Override
    public Boolean getClaimsParameterSupported() {
        return claimsParameterSupported;
    }

    /**
     *
     * @param claimsParameterSupported Boolean value specifying whether the OP supports use of the claims parameter.
     */
    public void setClaimsParameterSupported(@Nullable Boolean claimsParameterSupported) {
        this.claimsParameterSupported = claimsParameterSupported;
    }

    /**
     *
     * @param claimsSupported List of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for.
     */
    public void setClaimsSupported(@Nullable List<String> claimsSupported) {
        this.claimsSupported = claimsSupported;
    }

    @Nullable
    @Override
    public List<String> getCodeChallengeMethodsSupported() {
        return codeChallengeMethodsSupported;
    }

    /**
     *
     * @param codeChallengeMethodsSupported List of the supported transformation methods by the authorisation code verifier for Proof Key for Code Exchange (PKCE).
     */
    public void setCodeChallengeMethodsSupported(@Nullable List<String> codeChallengeMethodsSupported) {
        this.codeChallengeMethodsSupported = codeChallengeMethodsSupported;
    }

    @Nullable
    @Override
    public String getIntrospectionEndpoint() {
        return introspectionEndpoint;
    }

    /**
     *
     * @param introspectionEndpoint The fully qualified URL of the server's introspection endpoint defined by OAuth Token Introspection [RFC7662].
     */
    public void setIntrospectionEndpoint(@Nullable String introspectionEndpoint) {
        this.introspectionEndpoint = introspectionEndpoint;
    }

    @Nullable
    @Override
    public List<String> getIntrospectionEndpointAuthMethodsSupported() {
        return introspectionEndpointAuthMethodsSupported;
    }

    /**
     *
     * @param introspectionEndpointAuthMethodsSupported List of Client Authentication methods supported by Introspection Endpoint.
     */
    public void setIntrospectionEndpointAuthMethodsSupported(@Nullable List<String> introspectionEndpointAuthMethodsSupported) {
        this.introspectionEndpointAuthMethodsSupported = introspectionEndpointAuthMethodsSupported;
    }

    @Nullable
    @Override
    public String getRevocationEndpoint() {
        return revocationEndpoint;
    }

    /**
     *
     * @param revocationEndpoint The fully qualified URL of the server's revocation endpoint defined by Oauth Token Revocation.
     */
    public void setRevocationEndpoint(@Nullable String revocationEndpoint) {
        this.revocationEndpoint = revocationEndpoint;
    }

    @Nullable
    @Override
    public List<String> getRevocationEndpointAuthMethodsSupported() {
        return revocationEndpointAuthMethodsSupported;
    }

    /**
     *
     * @param revocationEndpointAuthMethodsSupported List of Client Authentication methods supported by Revocation Endpoint.
     */
    public void setRevocationEndpointAuthMethodsSupported(@Nullable List<String> revocationEndpointAuthMethodsSupported) {
        this.revocationEndpointAuthMethodsSupported = revocationEndpointAuthMethodsSupported;
    }

    /**
     *
     * @param checkSessionIframe URL of an OP iframe that supports cross-origin communications for session state information with the RP Client, using the HTML5 postMessage API.
     */
    public void setCheckSessionIframe(@Nullable String checkSessionIframe) {
        this.checkSessionIframe = checkSessionIframe;
    }

    @Nullable
    @Override
    public String getCheckSessionIframe() {
        return checkSessionIframe;
    }

    @Nullable
    @Override
    public String getEndSessionEndpoint() {
        return endSessionEndpoint;
    }

    /**
     *
     * @param endSessionEndpoint URL at the OP to which an RP can perform a redirect to request that the End-User be logged out at the OP.
     */
    public void setEndSessionEndpoint(@Nullable String endSessionEndpoint) {
        this.endSessionEndpoint = endSessionEndpoint;
    }

    @Nullable
    @Override
    public Boolean getRequestParameterSupported() {
        return requestParameterSupported;
    }

    /**
     * @return As per spec, If requestParameterSupported omitted, the default value is false.
     */
    @NonNull
    public Boolean getDefaultRequestParameterSupported() {
        return Boolean.FALSE;
    }

    @Nullable
    @Override
    public Boolean getRequestUriParameterSupported() {
        return requestUriParameterSupported;
    }

    /**
     * @return As per spec, If requestUriParameterSupported omitted, the default value is false.
     */
    @NonNull
    public Boolean getDefaultRequestUriParameterSupported() {
        return Boolean.TRUE;
    }

    /**
     *
     * @param requestUriParameterSupported  Boolean value specifying whether the OP requires any request_uri values used to be pre-registered using the request_uris registration parameter.
     */
    public void setRequestUriParameterSupported(@Nullable Boolean requestUriParameterSupported) {
        this.requestUriParameterSupported = requestUriParameterSupported;
    }

    @Nullable
    @Override
    public String getOpPolicyUri() {
        return opPolicyUri;
    }

    /**
     *
     * @param opPolicyUri URL that the OpenID Provider provides to the person registering the Client to read about the OP's requirements on how the Relying Party can use the data provided by the OP.
     */
    public void setOpPolicyUri(@Nullable String opPolicyUri) {
        this.opPolicyUri = opPolicyUri;
    }

    @Nullable
    @Override
    public String getOpTosUri() {
        return opTosUri;
    }

    /**
     *
     * @param opTosUri URL that the OpenID Provider provides to the person registering the Client to read about OpenID Provider's terms of service.
     */
    public void setOpTosUri(@Nullable String opTosUri) {
        this.opTosUri = opTosUri;
    }

    /**
     *
     * @param requestParameterSupported Boolean value specifying whether the OP supports use of the request parameter, with true indicating support.
     */
    public void setRequestParameterSupported(@Nullable Boolean requestParameterSupported) {
        this.requestParameterSupported = requestParameterSupported;
    }

    @Nullable
    @Override
    public List<String> getRequestObjectSigningAlgValuesSupported() {
        return requestObjectSigningAlgValuesSupported;
    }

    @Nullable
    @Override
    public List<String> getRequestObjectEncryptionAlgValuesSupported() {
        return requestObjectEncryptionAlgValuesSupported;
    }

    /**
     *
     * @param requestObjectEncryptionAlgValuesSupported List of the JWE encryption algorithms (alg values) supported by the OP for Request Objects.
     */
    public void setRequestObjectEncryptionAlgValuesSupported(@Nullable List<String> requestObjectEncryptionAlgValuesSupported) {
        this.requestObjectEncryptionAlgValuesSupported = requestObjectEncryptionAlgValuesSupported;
    }

    @Nullable
    @Override
    public List<String> getRequestObjectEncryptionEncValuesSupported() {
        return requestObjectEncryptionEncValuesSupported;
    }

    /**
     *
     * @param requestObjectEncryptionEncValuesSupported List of the JWE encryption algorithms (enc values) supported by the OP for Request Objects.
     */
    public void setRequestObjectEncryptionEncValuesSupported(@Nullable List<String> requestObjectEncryptionEncValuesSupported) {
        this.requestObjectEncryptionEncValuesSupported = requestObjectEncryptionEncValuesSupported;
    }

    /**
     *
     * @param requestObjectSigningAlgValuesSupported List of the JWS signing algorithms (alg values) supported by the OP for Request Objects.
     */
    public void setRequestObjectSigningAlgValuesSupported(@Nullable List<String> requestObjectSigningAlgValuesSupported) {
        this.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        DefaultOpenIdProviderMetadata that = (DefaultOpenIdProviderMetadata) o;

        if (providerName != null ? !providerName.equals(that.providerName) : that.providerName != null) {
            return false;
        }
        if (authorizationEndpoint != null ? !authorizationEndpoint.equals(that.authorizationEndpoint) : that.authorizationEndpoint != null) {
            return false;
        }
        if (idTokenSigningAlgValuesSupported != null ? !idTokenSigningAlgValuesSupported.equals(that.idTokenSigningAlgValuesSupported) : that.idTokenSigningAlgValuesSupported != null) {
            return false;
        }
        if (issuer != null ? !issuer.equals(that.issuer) : that.issuer != null) {
            return false;
        }
        if (jwksUri != null ? !jwksUri.equals(that.jwksUri) : that.jwksUri != null) {
            return false;
        }
        if (acrValuesSupported != null ? !acrValuesSupported.equals(that.acrValuesSupported) : that.acrValuesSupported != null) {
            return false;
        }
        if (responseTypesSupported != null ? !responseTypesSupported.equals(that.responseTypesSupported) : that.responseTypesSupported != null) {
            return false;
        }
        if (responseModesSupported != null ? !responseModesSupported.equals(that.responseModesSupported) : that.responseModesSupported != null) {
            return false;
        }
        if (scopesSupported != null ? !scopesSupported.equals(that.scopesSupported) : that.scopesSupported != null) {
            return false;
        }
        if (grantTypesSupported != null ? !grantTypesSupported.equals(that.grantTypesSupported) : that.grantTypesSupported != null) {
            return false;
        }
        if (subjectTypesSupported != null ? !subjectTypesSupported.equals(that.subjectTypesSupported) : that.subjectTypesSupported != null) {
            return false;
        }
        if (tokenEndpoint != null ? !tokenEndpoint.equals(that.tokenEndpoint) : that.tokenEndpoint != null) {
            return false;
        }
        if (tokenEndpointAuthMethodsSupported != null ? !tokenEndpointAuthMethodsSupported.equals(that.tokenEndpointAuthMethodsSupported) : that.tokenEndpointAuthMethodsSupported != null) {
            return false;
        }
        if (userinfoEndpoint != null ? !userinfoEndpoint.equals(that.userinfoEndpoint) : that.userinfoEndpoint != null) {
            return false;
        }
        if (registrationEndpoint != null ? !registrationEndpoint.equals(that.registrationEndpoint) : that.registrationEndpoint != null) {
            return false;
        }
        if (claimsSupported != null ? !claimsSupported.equals(that.claimsSupported) : that.claimsSupported != null) {
            return false;
        }
        if (codeChallengeMethodsSupported != null ? !codeChallengeMethodsSupported.equals(that.codeChallengeMethodsSupported) : that.codeChallengeMethodsSupported != null) {
            return false;
        }
        if (introspectionEndpoint != null ? !introspectionEndpoint.equals(that.introspectionEndpoint) : that.introspectionEndpoint != null) {
            return false;
        }
        if (introspectionEndpointAuthMethodsSupported != null ? !introspectionEndpointAuthMethodsSupported.equals(that.introspectionEndpointAuthMethodsSupported) : that.introspectionEndpointAuthMethodsSupported != null) {
            return false;
        }
        if (revocationEndpoint != null ? !revocationEndpoint.equals(that.revocationEndpoint) : that.revocationEndpoint != null) {
            return false;
        }
        if (revocationEndpointAuthMethodsSupported != null ? !revocationEndpointAuthMethodsSupported.equals(that.revocationEndpointAuthMethodsSupported) : that.revocationEndpointAuthMethodsSupported != null) {
            return false;
        }
        if (endSessionEndpoint != null ? !endSessionEndpoint.equals(that.endSessionEndpoint) : that.endSessionEndpoint != null) {
            return false;
        }
        if (requestParameterSupported != null ? !requestParameterSupported.equals(that.requestParameterSupported) : that.requestParameterSupported != null) {
            return false;
        }
        if (requestUriParameterSupported != null ? !requestUriParameterSupported.equals(that.requestUriParameterSupported) : that.requestUriParameterSupported != null) {
            return false;
        }
        if (requireRequestUriRegistration != null ? !requireRequestUriRegistration.equals(that.requireRequestUriRegistration) : that.requireRequestUriRegistration != null) {
            return false;
        }
        if (requestObjectSigningAlgValuesSupported != null ? !requestObjectSigningAlgValuesSupported.equals(that.requestObjectSigningAlgValuesSupported) : that.requestObjectSigningAlgValuesSupported != null) {
            return false;
        }
        if (serviceDocumentation != null ? !serviceDocumentation.equals(that.serviceDocumentation) : that.serviceDocumentation != null) {
            return false;
        }
        if (idTokenEncryptionEncValuesSupported != null ? !idTokenEncryptionEncValuesSupported.equals(that.idTokenEncryptionEncValuesSupported) : that.idTokenEncryptionEncValuesSupported != null) {
            return false;
        }
        if (displayValuesSupported != null ? !displayValuesSupported.equals(that.displayValuesSupported) : that.displayValuesSupported != null) {
            return false;
        }
        if (claimTypesSupported != null ? !claimTypesSupported.equals(that.claimTypesSupported) : that.claimTypesSupported != null) {
            return false;
        }
        if (claimsParameterSupported != null ? !claimsParameterSupported.equals(that.claimsParameterSupported) : that.claimsParameterSupported != null) {
            return false;
        }
        if (opTosUri != null ? !opTosUri.equals(that.opTosUri) : that.opTosUri != null) {
            return false;
        }
        if (opPolicyUri != null ? !opPolicyUri.equals(that.opPolicyUri) : that.opPolicyUri != null) {
            return false;
        }
        if (uriLocalesSupported != null ? !uriLocalesSupported.equals(that.uriLocalesSupported) : that.uriLocalesSupported != null) {
            return false;
        }
        if (claimsLocalesSupported != null ? !claimsLocalesSupported.equals(that.claimsLocalesSupported) : that.claimsLocalesSupported != null) {
            return false;
        }
        if (userinfoEncryptionAlgValuesSupported != null ? !userinfoEncryptionAlgValuesSupported.equals(that.userinfoEncryptionAlgValuesSupported) : that.userinfoEncryptionAlgValuesSupported != null) {
            return false;
        }
        if (userinfoEncryptionEncValuesSupported != null ? !userinfoEncryptionEncValuesSupported.equals(that.userinfoEncryptionEncValuesSupported) : that.userinfoEncryptionEncValuesSupported != null) {
            return false;
        }
        if (tokenEndpointAuthSigningAlgValuesSupported != null ? !tokenEndpointAuthSigningAlgValuesSupported.equals(that.tokenEndpointAuthSigningAlgValuesSupported) : that.tokenEndpointAuthSigningAlgValuesSupported != null) {
            return false;
        }
        if (requestObjectEncryptionAlgValuesSupported != null ? !requestObjectEncryptionAlgValuesSupported.equals(that.requestObjectEncryptionAlgValuesSupported) : that.requestObjectEncryptionAlgValuesSupported != null) {
            return false;
        }
        if (requestObjectEncryptionEncValuesSupported != null ? !requestObjectEncryptionEncValuesSupported.equals(that.requestObjectEncryptionEncValuesSupported) : that.requestObjectEncryptionEncValuesSupported != null) {
            return false;
        }
        return checkSessionIframe != null ? checkSessionIframe.equals(that.checkSessionIframe) : that.checkSessionIframe == null;
    }

    @Override
    public int hashCode() {
        int result = providerName != null ? providerName.hashCode() : 0;
        result = 31 * result + (authorizationEndpoint != null ? authorizationEndpoint.hashCode() : 0);
        result = 31 * result + (idTokenSigningAlgValuesSupported != null ? idTokenSigningAlgValuesSupported.hashCode() : 0);
        result = 31 * result + (issuer != null ? issuer.hashCode() : 0);
        result = 31 * result + (jwksUri != null ? jwksUri.hashCode() : 0);
        result = 31 * result + (acrValuesSupported != null ? acrValuesSupported.hashCode() : 0);
        result = 31 * result + (responseTypesSupported != null ? responseTypesSupported.hashCode() : 0);
        result = 31 * result + (responseModesSupported != null ? responseModesSupported.hashCode() : 0);
        result = 31 * result + (scopesSupported != null ? scopesSupported.hashCode() : 0);
        result = 31 * result + (grantTypesSupported != null ? grantTypesSupported.hashCode() : 0);
        result = 31 * result + (subjectTypesSupported != null ? subjectTypesSupported.hashCode() : 0);
        result = 31 * result + (tokenEndpoint != null ? tokenEndpoint.hashCode() : 0);
        result = 31 * result + (tokenEndpointAuthMethodsSupported != null ? tokenEndpointAuthMethodsSupported.hashCode() : 0);
        result = 31 * result + (userinfoEndpoint != null ? userinfoEndpoint.hashCode() : 0);
        result = 31 * result + (registrationEndpoint != null ? registrationEndpoint.hashCode() : 0);
        result = 31 * result + (claimsSupported != null ? claimsSupported.hashCode() : 0);
        result = 31 * result + (codeChallengeMethodsSupported != null ? codeChallengeMethodsSupported.hashCode() : 0);
        result = 31 * result + (introspectionEndpoint != null ? introspectionEndpoint.hashCode() : 0);
        result = 31 * result + (introspectionEndpointAuthMethodsSupported != null ? introspectionEndpointAuthMethodsSupported.hashCode() : 0);
        result = 31 * result + (revocationEndpoint != null ? revocationEndpoint.hashCode() : 0);
        result = 31 * result + (revocationEndpointAuthMethodsSupported != null ? revocationEndpointAuthMethodsSupported.hashCode() : 0);
        result = 31 * result + (endSessionEndpoint != null ? endSessionEndpoint.hashCode() : 0);
        result = 31 * result + (requestParameterSupported != null ? requestParameterSupported.hashCode() : 0);
        result = 31 * result + (requestUriParameterSupported != null ? requestUriParameterSupported.hashCode() : 0);
        result = 31 * result + (requireRequestUriRegistration != null ? requireRequestUriRegistration.hashCode() : 0);
        result = 31 * result + (requestObjectSigningAlgValuesSupported != null ? requestObjectSigningAlgValuesSupported.hashCode() : 0);
        result = 31 * result + (serviceDocumentation != null ? serviceDocumentation.hashCode() : 0);
        result = 31 * result + (idTokenEncryptionEncValuesSupported != null ? idTokenEncryptionEncValuesSupported.hashCode() : 0);
        result = 31 * result + (displayValuesSupported != null ? displayValuesSupported.hashCode() : 0);
        result = 31 * result + (claimTypesSupported != null ? claimTypesSupported.hashCode() : 0);
        result = 31 * result + (claimsParameterSupported != null ? claimsParameterSupported.hashCode() : 0);
        result = 31 * result + (opTosUri != null ? opTosUri.hashCode() : 0);
        result = 31 * result + (opPolicyUri != null ? opPolicyUri.hashCode() : 0);
        result = 31 * result + (uriLocalesSupported != null ? uriLocalesSupported.hashCode() : 0);
        result = 31 * result + (claimsLocalesSupported != null ? claimsLocalesSupported.hashCode() : 0);
        result = 31 * result + (userinfoEncryptionAlgValuesSupported != null ? userinfoEncryptionAlgValuesSupported.hashCode() : 0);
        result = 31 * result + (userinfoEncryptionEncValuesSupported != null ? userinfoEncryptionEncValuesSupported.hashCode() : 0);
        result = 31 * result + (tokenEndpointAuthSigningAlgValuesSupported != null ? tokenEndpointAuthSigningAlgValuesSupported.hashCode() : 0);
        result = 31 * result + (requestObjectEncryptionAlgValuesSupported != null ? requestObjectEncryptionAlgValuesSupported.hashCode() : 0);
        result = 31 * result + (requestObjectEncryptionEncValuesSupported != null ? requestObjectEncryptionEncValuesSupported.hashCode() : 0);
        result = 31 * result + (checkSessionIframe != null ? checkSessionIframe.hashCode() : 0);
        return result;
    }

    /**
     *
     * @return Creates a Builder.
     * @deprecated Use {@link DefaultOpenIdProviderMetadata(String)} instead.
     */
    @Deprecated(forRemoval = true, since = "4.5.0")
    @NonNull
    public static Builder builder() {
        return new Builder("");
    }

    /**
     * @param providerName Provider Name
     * @return Creates a Builder with a given provider name.
     */
    @NonNull
    public static Builder builder(String providerName) {
        return new Builder(providerName);
    }

    /**
     * Builder.
     */
    public static class Builder {

        @NonNull
        private final String providerName;

        @Nullable
        private String authorizationEndpoint;

        @NonNull
        private List<String> idTokenSigningAlgValuesSupported;

        @NonNull
        private String issuer;
        @NonNull
        private String jwksUri;

        @Nullable
        private List<String> acrValuesSupported;
        @Nullable
        private List<String> responseTypesSupported;
        @Nullable
        private List<String> responseModesSupported;
        @Nullable
        private List<String> scopesSupported;

        @Nullable
        private List<String> grantTypesSupported;

        @NonNull
        private List<String> subjectTypesSupported;
        @NonNull
        private String tokenEndpoint;

        @Nullable
        private List<String> tokenEndpointAuthMethodsSupported;

        @Nullable
        private String userinfoEndpoint;

        @Nullable
        private String registrationEndpoint;
        @Nullable private List<String> claimsSupported;
        @Nullable
        private List<String> codeChallengeMethodsSupported;
        @Nullable
        private String introspectionEndpoint;
        @Nullable
        private List<String> introspectionEndpointAuthMethodsSupported;
        @Nullable
        private String revocationEndpoint;
        @Nullable
        private List<String> revocationEndpointAuthMethodsSupported;
        @Nullable
        private String endSessionEndpoint;
        @Nullable
        private Boolean requestParameterSupported;
        @Nullable
        private Boolean requestUriParameterSupported;
        @Nullable
        private Boolean requireRequestUriRegistration;
        @Nullable
        private List<String> requestObjectSigningAlgValuesSupported;
        @Nullable
        private String serviceDocumentation;
        @Nullable
        private List<String> idTokenEncryptionEncValuesSupported;
        @Nullable
        private List<String> displayValuesSupported;
        @Nullable
        private List<String> claimTypesSupported;

        @NonNull
        private Boolean claimsParameterSupported = Boolean.FALSE;

        @Nullable
        private String opTosUri;
        @Nullable
        private String opPolicyUri;
        @Nullable
        private List<String> uriLocalesSupported;
        @Nullable
        private List<String> claimsLocalesSupported;
        @Nullable
        private List<String> userinfoEncryptionAlgValuesSupported;
        @Nullable
        private List<String> userinfoEncryptionEncValuesSupported;
        @Nullable
        private List<String> tokenEndpointAuthSigningAlgValuesSupported;
        @Nullable
        private List<String> requestObjectEncryptionAlgValuesSupported;
        @Nullable
        private List<String> requestObjectEncryptionEncValuesSupported;
        @Nullable
        private String checkSessionIframe;

        /**
         * @deprecated Use {@link Builder(String)} instead.
         */
        @Deprecated(forRemoval = true, since = "4.5.0")
        public Builder() {
            this("");
        }

        /**
         *
         * @param providerName The configured Open ID provider name
         */
        public Builder(String providerName) {
            this.providerName = providerName;
        }

        /**
         *
         * @param authorizationEndpoint URL of the Open ID Provider's OAuth 2.0 Authorization Endpoint
         * @return The Builder
         */
        @NonNull
        public Builder authorizationEndpoint(@Nullable String authorizationEndpoint) {
            this.authorizationEndpoint = authorizationEndpoint;
            return this;
        }

        /**
         *
         * @param idTokenSigningAlgValuesSupported List of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
         * @return The Builder
         */
        @NonNull
        public Builder idTokenSigningAlgValuesSupported(@NonNull List<String> idTokenSigningAlgValuesSupported) {
            this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
            return this;
        }

        /**
         *
         * @param issuer URL using the https scheme with no query or fragment component that the Open ID Provider asserts as its Issuer Identifier.
         * @return The Builder
         */
        @NonNull
        public Builder issuer(@NonNull String issuer) {
            this.issuer = issuer;
            return this;
        }

        /**
         *
         * @param jwksUri URL of the Open ID Provider's JSON Web Key Set
         * @return The Builder
         */
        @NonNull
        public Builder jwksUri(@NonNull String jwksUri) {
            this.jwksUri = jwksUri;
            return this;
        }

        /**
         *
         * @param acrValuesSupported List of the Authentication Context Class References that this OP supports.
         * @return The Builder
         */
        @NonNull
        public Builder acrValuesSupported(@NonNull List<String> acrValuesSupported) {
            this.acrValuesSupported = acrValuesSupported;
            return this;
        }

        /**
         *
         * @param responseTypesSupported List of the OAuth 2.0 response_type values that this Open ID Provider supports.
         * @return The Builder
         */
        @NonNull
        public Builder responseTypesSupported(@Nullable List<String> responseTypesSupported) {
            this.responseTypesSupported = responseTypesSupported;
            return this;
        }

        /**
         *
         * @param responseModesSupported List of the OAuth 2.0 response_mode values that this Open ID Provider supports.
         * @return The Builder
         */
        @NonNull
        public Builder responseModesSupported(@Nullable List<String> responseModesSupported) {
            this.responseModesSupported = responseModesSupported;
            return this;
        }

        /**
         *
         * @param scopesSupported List of the OAuth 2.0 [RFC6749] scope values that this server supports.
         * @return The Builder
         */
        @NonNull
        public Builder scopesSupported(@Nullable List<String> scopesSupported) {
            this.scopesSupported = scopesSupported;
            return this;
        }

        /**
         *
         * @param grantTypesSupported List of the OAuth 2.0 Grant Type values that this Open ID Provider supports.
         * @return The Builder
         */
        @NonNull
        public Builder grantTypesSupported(@Nullable List<String> grantTypesSupported) {
            this.grantTypesSupported = grantTypesSupported;
            return this;
        }

        /**
         *
         * @param subjectTypesSupported List of the Subject Identifier types that this OP supports.
         * @return The Builder
         */
        @NonNull
        public Builder subjectTypesSupported(@NonNull List<String> subjectTypesSupported) {
            this.subjectTypesSupported = subjectTypesSupported;
            return this;
        }

        /**
         *
         * @param tokenEndpoint URL of the Open ID Provider's OAuth 2.0 Token Endpoint
         * @return The Builder
         */
        @NonNull
        public Builder tokenEndpoint(@NonNull String tokenEndpoint) {
            this.tokenEndpoint = tokenEndpoint;
            return this;
        }

        /**
         *
         * @param tokenEndpointAuthMethodsSupported List of Client Authentication methods supported by this Token Endpoint.
         * @return The Builder
         */
        @NonNull
        public Builder tokenEndpointAuthMethodsSupported(@Nullable List<String> tokenEndpointAuthMethodsSupported) {
            this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
            return this;
        }

        /**
         *
         * @param userinfoEndpoint URL of the Open ID Provider's UserInfo Endpoint
         * @return The Builder
         */
        @NonNull
        public Builder userinfoEndpoint(@Nullable String userinfoEndpoint) {
            this.userinfoEndpoint = userinfoEndpoint;
            return this;
        }

        /**
         *
         * @param registrationEndpoint URL of the Open ID Provider's Dynamic Client Registration Endpoint
         * @return The Builder
         */
        @NonNull
        public Builder registrationEndpoint(@Nullable String registrationEndpoint) {
            this.registrationEndpoint = registrationEndpoint;
            return this;
        }

        /**
         *
         * @param claimsSupported List of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for.
         * @return The Builder
         */
        @NonNull
        public Builder claimsSupported(@Nullable List<String> claimsSupported) {
            this.claimsSupported = claimsSupported;
            return this;
        }

        /**
         *
         * @param codeChallengeMethodsSupported List of the supported transformation methods by the authorisation code verifier for Proof Key for Code Exchange (PKCE).
         * @return The Builder
         */
        @NonNull
        public Builder codeChallengeMethodsSupported(@Nullable List<String> codeChallengeMethodsSupported) {
            this.codeChallengeMethodsSupported = codeChallengeMethodsSupported;
            return this;
        }

        /**
         *
         * @param introspectionEndpoint The fully qualified URL of the server's introspection endpoint defined by OAuth Token Introspection [RFC7662]
         * @return The Builder
         */
        @NonNull
        public Builder introspectionEndpoint(@Nullable String introspectionEndpoint) {
            this.introspectionEndpoint = introspectionEndpoint;
            return this;
        }

        /**
         *
         * @param introspectionEndpointAuthMethodsSupported List of Client Authentication methods supported by Introspection Endpoint
         * @return The Builder
         */
        @NonNull
        public Builder introspectionEndpointAuthMethodsSupported(@Nullable List<String> introspectionEndpointAuthMethodsSupported) {
            this.introspectionEndpointAuthMethodsSupported = introspectionEndpointAuthMethodsSupported;
            return this;
        }


        /**
         *
         * @param revocationEndpoint The fully qualified URL of the server's revocation endpoint defined by Oauth Token Revocation.
         * @return The Builder
         */
        @NonNull
        public Builder revocationEndpoint(@Nullable String revocationEndpoint) {
            this.revocationEndpoint = revocationEndpoint;
            return this;
        }

        /**
         *
         * @param revocationEndpointAuthMethodsSupported List of Client Authentication methods supported by Revocation Endpoint
         * @return The Builder
         */
        @NonNull
        public Builder revocationEndpointAuthMethodsSupported(@Nullable List<String> revocationEndpointAuthMethodsSupported) {
            this.revocationEndpointAuthMethodsSupported = revocationEndpointAuthMethodsSupported;
            return this;
        }

        /**
         *
         * @param endSessionEndpoint URL at the OP to which an RP can perform a redirect to request that the End-User be logged out at the OP.
         * @return The Builder
         */
        @NonNull
        public Builder endSessionEndpoint(@Nullable String endSessionEndpoint) {
            this.endSessionEndpoint = endSessionEndpoint;
            return this;
        }

        /**
         *
         * @param requestParameterSupported Boolean value specifying whether the OP supports use of the request parameter, with true indicating support.
         * @return The Builder
         */
        @NonNull
        public Builder requestParameterSupported(@Nullable Boolean requestParameterSupported) {
            this.requestParameterSupported = requestParameterSupported;
            return this;
        }

        /**
         *
         * @param requestUriParameterSupported Boolean value specifying whether the OP supports use of the request_uri parameter, with true indicating support.
         * @return The Builder
         */
        @NonNull
        public Builder requestUriParameterSupported(@Nullable Boolean requestUriParameterSupported) {
            this.requestUriParameterSupported = requestUriParameterSupported;
            return this;
        }

        /**
         *
         * @param requireRequestUriRegistration Boolean value specifying whether the OP requires any request_uri values used to be pre-registered using the request_uris registration parameter. Pre-registration is REQUIRED when the value is true. If omitted, the default value is false.
         * @return The Builder
         */
        @NonNull
        public Builder requireRequestUriRegistration(@Nullable Boolean requireRequestUriRegistration) {
            this.requireRequestUriRegistration = requireRequestUriRegistration;
            return this;
        }

        /**
         *
         * @param requestObjectSigningAlgValuesSupported List of the JWS signing algorithms (alg values) supported by the OP for Request Objects.
         * @return The Builder
         */
        @NonNull
        public Builder requestObjectSigningAlgValuesSupported(@Nullable List<String> requestObjectSigningAlgValuesSupported) {
            this.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported;
            return this;
        }

        /**
         *
         * @param serviceDocumentation URL of a page containing human-readable information that developers might want or need to know when using the OpenID Provider.
         * @return The Builder
         */
        @NonNull
        public Builder serviceDocumentation(@Nullable String serviceDocumentation) {
            this.serviceDocumentation = serviceDocumentation;
            return this;
        }

        /**
         *
         * @param idTokenEncryptionEncValuesSupported List of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
         * @return The Builder
         */
        @NonNull
        public Builder idTokenEncryptionEncValuesSupported(@Nullable List<String> idTokenEncryptionEncValuesSupported) {
            this.idTokenEncryptionEncValuesSupported = idTokenEncryptionEncValuesSupported;
            return this;
        }

        /**
         *
         * @param displayValuesSupported List of the display parameter values that the OpenID Provider supports.
         * @return The Builder
         */
        @NonNull
        public Builder displayValuesSupported(@Nullable List<String> displayValuesSupported) {
            this.displayValuesSupported = displayValuesSupported;
            return this;
        }

        /**
         *
         * @param claimTypesSupported List of the Claim Types that the OpenID Provider supports.
         * @return The Builder
         */
        @NonNull
        public Builder claimTypesSupported(@Nullable List<String> claimTypesSupported) {
            this.claimTypesSupported = claimTypesSupported;
            return this;
        }

        /**
         *
         * @param claimsParameterSupported Boolean value specifying whether the OP supports use of the claims parameter.
         * @return The Builder
         */
        @NonNull
        public Builder claimsParameterSupported(@NonNull Boolean claimsParameterSupported) {
            this.claimsParameterSupported = claimsParameterSupported;
            return this;
        }



        /**
         *
         * @param opTosUri URL that the OpenID Provider provides to the person registering the Client to read about OpenID Provider's terms of service.
         * @return The Builder
         */
        @NonNull
        public Builder opTosUri(@Nullable String opTosUri) {
            this.opTosUri = opTosUri;
            return this;
        }

        /**
         *
         * @param opPolicyUri URL that the OpenID Provider provides to the person registering the Client to read about the OP's requirements on how the Relying Party can use the data provided by the OP.
         * @return The Builder
         */
        @NonNull
        public Builder opPolicyUri(@Nullable String opPolicyUri) {
            this.opPolicyUri = opPolicyUri;
            return this;
        }

        /**
         *
         * @param uriLocalesSupported Languages and scripts supported for the user interface
         * @return The Builder
         */
        @NonNull
        public Builder uriLocalesSupported(@Nullable List<String> uriLocalesSupported) {
            this.uriLocalesSupported = uriLocalesSupported;
            return this;
        }

        /**
         *
         * @param claimsLocalesSupported Languages and scripts supported for values in Claims
         * @return The Builder
         */
        @NonNull
        public Builder claimsLocalesSupported(@Nullable List<String> claimsLocalesSupported) {
            this.claimsLocalesSupported = claimsLocalesSupported;
            return this;
        }

        /**
         *
         * @param userinfoEncryptionAlgValuesSupported List of the JWE [JWE] encryption algorithms (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
         * @return The Builder
         */
        @NonNull
        public Builder userinfoEncryptionAlgValuesSupported(@Nullable List<String> userinfoEncryptionAlgValuesSupported) {
            this.userinfoEncryptionAlgValuesSupported = userinfoEncryptionAlgValuesSupported;
            return this;
        }

        /**
         *
         * @param userinfoEncryptionEncValuesSupported List of the JWE encryption algorithms (enc values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
         * @return The Builder
         */
        @NonNull
        public Builder userinfoEncryptionEncValuesSupported(@Nullable List<String> userinfoEncryptionEncValuesSupported) {
            this.userinfoEncryptionEncValuesSupported = userinfoEncryptionEncValuesSupported;
            return this;
        }

        /**
         *
         * @param tokenEndpointAuthSigningAlgValuesSupported List of the JWS signing algorithms (alg values) supported by the Token Endpoint.
         * @return The Builder
         */
        @NonNull
        public Builder tokenEndpointAuthSigningAlgValuesSupported(@Nullable List<String> tokenEndpointAuthSigningAlgValuesSupported) {
            this.tokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported;
            return this;
        }

        /**
         *
         * @param requestObjectEncryptionAlgValuesSupported list of the JWE encryption algorithms (alg values) supported by the OP for Request Objects.
         * @return The Builder
         */
        @NonNull
        public Builder requestObjectEncryptionAlgValuesSupported(@Nullable List<String> requestObjectEncryptionAlgValuesSupported) {
            this.requestObjectEncryptionAlgValuesSupported = requestObjectEncryptionAlgValuesSupported;
            return this;
        }

        /**
         *
         * @param requestObjectEncryptionEncValuesSupported List of the JWE encryption algorithms (enc values) supported by the OP for Request Objects.
         * @return The Builder
         */
        @NonNull
        public Builder requestObjectEncryptionEncValuesSupported(@Nullable List<String> requestObjectEncryptionEncValuesSupported) {
            this.requestObjectEncryptionEncValuesSupported = requestObjectEncryptionEncValuesSupported;
            return this;
        }

        /**
         *
         * @param checkSessionIframe URL of an OP iframe that supports cross-origin communications for session state information with the RP Client, using the HTML5 postMessage API.
         * @return The Builder
         */
        @NonNull
        public Builder checkSessionIframe(@Nullable String checkSessionIframe) {
            this.checkSessionIframe = checkSessionIframe;
            return this;
        }

        /**
         *
         * @return a {@link DefaultOpenIdProviderMetadata} instance.
         */
        @NonNull
        public DefaultOpenIdProviderMetadata build() {
            DefaultOpenIdProviderMetadata metadata = new DefaultOpenIdProviderMetadata(providerName);
            metadata.setAuthorizationEndpoint(Objects.requireNonNull(authorizationEndpoint));
            metadata.setIdTokenSigningAlgValuesSupported(idTokenSigningAlgValuesSupported);
            metadata.setIssuer(issuer);
            metadata.setJwksUri(jwksUri);
            metadata.setAcrValuesSupported(acrValuesSupported);
            metadata.setResponseTypesSupported(responseTypesSupported);
            metadata.setResponseModesSupported(responseModesSupported);
            metadata.setScopesSupported(scopesSupported);
            metadata.setGrantTypesSupported(grantTypesSupported);
            metadata.setSubjectTypesSupported(subjectTypesSupported);
            metadata.setTokenEndpoint(tokenEndpoint);
            metadata.setTokenEndpointAuthMethodsSupported(tokenEndpointAuthMethodsSupported);
            metadata.setUserinfoEndpoint(userinfoEndpoint);
            metadata.setRegistrationEndpoint(registrationEndpoint);
            metadata.setClaimsSupported(claimsSupported);
            metadata.setCodeChallengeMethodsSupported(codeChallengeMethodsSupported);
            metadata.setIntrospectionEndpoint(introspectionEndpoint);
            metadata.setIntrospectionEndpointAuthMethodsSupported(introspectionEndpointAuthMethodsSupported);
            metadata.setRevocationEndpoint(revocationEndpoint);
            metadata.setRevocationEndpointAuthMethodsSupported(revocationEndpointAuthMethodsSupported);
            metadata.setEndSessionEndpoint(endSessionEndpoint);
            metadata.setRequestParameterSupported(requestParameterSupported);
            metadata.setRequestUriParameterSupported(requestUriParameterSupported);
            metadata.setRequireRequestUriRegistration(requireRequestUriRegistration);
            metadata.setRequestObjectSigningAlgValuesSupported(requestObjectSigningAlgValuesSupported);
            metadata.setServiceDocumentation(serviceDocumentation);
            metadata.setIdTokenEncryptionEncValuesSupported(idTokenEncryptionEncValuesSupported);
            metadata.setDisplayValuesSupported(displayValuesSupported);
            metadata.setClaimTypesSupported(claimTypesSupported);
            metadata.setClaimsParameterSupported(claimsParameterSupported);
            metadata.setOpTosUri(opTosUri);
            metadata.setOpPolicyUri(opPolicyUri);
            metadata.setUriLocalesSupported(uriLocalesSupported);
            metadata.setClaimsLocalesSupported(claimsLocalesSupported);
            metadata.setUserinfoEncryptionAlgValuesSupported(userinfoEncryptionAlgValuesSupported);
            metadata.setUserinfoEncryptionEncValuesSupported(userinfoEncryptionEncValuesSupported);
            metadata.setTokenEndpointAuthSigningAlgValuesSupported(tokenEndpointAuthSigningAlgValuesSupported);
            metadata.setRequestObjectEncryptionAlgValuesSupported(requestObjectEncryptionAlgValuesSupported);
            metadata.setRequestObjectEncryptionEncValuesSupported(requestObjectEncryptionEncValuesSupported);
            metadata.setCheckSessionIframe(checkSessionIframe);
            return metadata;
        }
    }
}
