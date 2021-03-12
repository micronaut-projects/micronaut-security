/*
 * Copyright 2017-2020 original authors
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

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.Introspected;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import java.util.Arrays;
import java.util.List;

/**
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID connect Discovery Spec</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Introspected
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class DefaultOpenIdProviderMetadata implements OpenIdProviderMetadata {

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
     * Empty Constructor.
     */
    public DefaultOpenIdProviderMetadata() {
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

    @Nullable
    @Override
    public List<String> getUserInfoEncryptionAlgValuesSupported() {
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
}
