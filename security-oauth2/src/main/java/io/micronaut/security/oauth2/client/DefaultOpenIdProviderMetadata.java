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

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.annotation.ReflectiveAccess;
import io.micronaut.serde.annotation.Serdeable;

import java.util.Arrays;
import java.util.List;

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

    @NonNull
    private final String authorizationEndpoint;

    @NonNull
    private final List<String> idTokenSigningAlgValuesSupported;

    @NonNull
    private final String issuer;

    @NonNull
    private final String jwksUri;

    @Nullable
    private final List<String> acrValuesSupported;

    @Nullable
    private final List<String> responseTypesSupported;

    @Nullable
    private final List<String> responseModesSupported;

    @Nullable
    private final List<String> scopesSupported;

    @Nullable
    private final List<String> grantTypesSupported;

    @NonNull
    private final List<String> subjectTypesSupported;

    @NonNull
    private final String tokenEndpoint;

    @Nullable
    private final List<String> tokenEndpointAuthMethodsSupported;

    @Nullable
    private final String userinfoEndpoint;

    @Nullable
    private final String registrationEndpoint;

    @Nullable
    private final List<String> claimsSupported;

    @Nullable
    private final List<String> codeChallengeMethodsSupported;

    @Nullable
    private final String introspectionEndpoint;

    @Nullable
    private final List<String> introspectionEndpointAuthMethodsSupported;

    @Nullable
    private final String revocationEndpoint;

    @Nullable
    private final List<String> revocationEndpointAuthMethodsSupported;

    @Nullable
    private final String endSessionEndpoint;

    @Nullable
    private final Boolean requestParameterSupported;

    @Nullable
    private final Boolean requestUriParameterSupported;

    @Nullable
    private final Boolean requireRequestUriRegistration;

    @Nullable
    private final List<String> requestObjectSigningAlgValuesSupported;

    @Nullable
    private final String serviceDocumentation;

    @Nullable
    private final List<String> idTokenEncryptionEncValuesSupported;

    @Nullable
    private final List<String> displayValuesSupported;

    @Nullable
    private final List<String> claimTypesSupported;

    @Nullable
    private final Boolean claimsParameterSupported;

    @Nullable
    private final String opTosUri;

    @Nullable
    private final String opPolicyUri;

    @Nullable
    private final List<String> uriLocalesSupported;

    @Nullable
    private final List<String> claimsLocalesSupported;

    @Nullable
    private final List<String> userinfoEncryptionAlgValuesSupported;

    @Nullable
    private final List<String> userinfoEncryptionEncValuesSupported;

    @Nullable
    private final List<String> tokenEndpointAuthSigningAlgValuesSupported;

    @Nullable
    private final List<String> requestObjectEncryptionAlgValuesSupported;

    @Nullable
    private final List<String> requestObjectEncryptionEncValuesSupported;

    @Nullable
    private final String checkSessionIframe;

    @SuppressWarnings("ParameterNumber")
    public DefaultOpenIdProviderMetadata(@Nullable String authorizationEndpoint,
                                         @NonNull List<String> idTokenSigningAlgValuesSupported,
                                         @NonNull String issuer,
                                         @NonNull String jwksUri,
                                         @Nullable List<String> acrValuesSupported,
                                         @Nullable List<String> responseTypesSupported,
                                         @Nullable List<String> responseModesSupported,
                                         @Nullable List<String> scopesSupported,
                                         @Nullable List<String> grantTypesSupported,
                                         @NonNull List<String> subjectTypesSupported,
                                         @NonNull String tokenEndpoint,
                                         @Nullable List<String> tokenEndpointAuthMethodsSupported,
                                         @Nullable String userinfoEndpoint,
                                         @Nullable String registrationEndpoint,
                                         @Nullable List<String> claimsSupported,
                                         @Nullable List<String> codeChallengeMethodsSupported,
                                         @Nullable String introspectionEndpoint,
                                         @Nullable List<String> introspectionEndpointAuthMethodsSupported,
                                         @Nullable String revocationEndpoint,
                                         @Nullable List<String> revocationEndpointAuthMethodsSupported,
                                         @Nullable String endSessionEndpoint,
                                         @Nullable Boolean requestParameterSupported,
                                         @Nullable Boolean requestUriParameterSupported,
                                         @Nullable Boolean requireRequestUriRegistration,
                                         @Nullable List<String> requestObjectSigningAlgValuesSupported,
                                         @Nullable String serviceDocumentation,
                                         @Nullable List<String> idTokenEncryptionEncValuesSupported,
                                         @Nullable List<String> displayValuesSupported,
                                         @Nullable List<String> claimTypesSupported,
                                         @Nullable Boolean claimsParameterSupported,
                                         @Nullable String opTosUri,
                                         @Nullable String opPolicyUri,
                                         @Nullable List<String> uriLocalesSupported,
                                         @Nullable List<String> claimsLocalesSupported,
                                         @Nullable List<String> userinfoEncryptionAlgValuesSupported,
                                         @Nullable List<String> userinfoEncryptionEncValuesSupported,
                                         @Nullable List<String> tokenEndpointAuthSigningAlgValuesSupported,
                                         @Nullable List<String> requestObjectEncryptionAlgValuesSupported,
                                         @Nullable List<String> requestObjectEncryptionEncValuesSupported,
                                         @Nullable String checkSessionIframe) {
        this.authorizationEndpoint = authorizationEndpoint;
        this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
        this.issuer = issuer;
        this.jwksUri = jwksUri;
        this.acrValuesSupported = acrValuesSupported;
        this.responseTypesSupported = responseTypesSupported;
        this.responseModesSupported = responseModesSupported;
        this.scopesSupported = scopesSupported;
        this.grantTypesSupported = grantTypesSupported;
        this.subjectTypesSupported = subjectTypesSupported;
        this.tokenEndpoint = tokenEndpoint;
        this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
        this.userinfoEndpoint = userinfoEndpoint;
        this.registrationEndpoint = registrationEndpoint;
        this.claimsSupported = claimsSupported;
        this.codeChallengeMethodsSupported = codeChallengeMethodsSupported;
        this.introspectionEndpoint = introspectionEndpoint;
        this.introspectionEndpointAuthMethodsSupported = introspectionEndpointAuthMethodsSupported;
        this.revocationEndpoint = revocationEndpoint;
        this.revocationEndpointAuthMethodsSupported = revocationEndpointAuthMethodsSupported;
        this.endSessionEndpoint = endSessionEndpoint;
        this.requestParameterSupported = requestParameterSupported;
        this.requestUriParameterSupported = requestUriParameterSupported;
        this.requireRequestUriRegistration = requireRequestUriRegistration;
        this.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported;
        this.serviceDocumentation = serviceDocumentation;
        this.idTokenEncryptionEncValuesSupported = idTokenEncryptionEncValuesSupported;
        this.displayValuesSupported = displayValuesSupported;
        this.claimTypesSupported = claimTypesSupported;
        this.claimsParameterSupported = claimsParameterSupported  != null ? claimsParameterSupported : Boolean.FALSE;
        this.opTosUri = opTosUri;
        this.opPolicyUri = opPolicyUri;
        this.uriLocalesSupported = uriLocalesSupported;
        this.claimsLocalesSupported = claimsLocalesSupported;
        this.userinfoEncryptionAlgValuesSupported = userinfoEncryptionAlgValuesSupported;
        this.userinfoEncryptionEncValuesSupported = userinfoEncryptionEncValuesSupported;
        this.tokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported;
        this.requestObjectEncryptionAlgValuesSupported = requestObjectEncryptionAlgValuesSupported;
        this.requestObjectEncryptionEncValuesSupported = requestObjectEncryptionEncValuesSupported;
        this.checkSessionIframe = checkSessionIframe;
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

    @Nullable
    @Override
    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
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

    @Nullable
    @Override
    public List<String> getUserInfoEncryptionAlgValuesSupported() {
        return userinfoEncryptionAlgValuesSupported;
    }

    @Nullable
    @Override
    public List<String> getUserinfoEncryptionEncValuesSupported() {
        return userinfoEncryptionEncValuesSupported;
    }

    @NonNull
    @Override
    public String getIssuer() {
        return issuer;
    }

    @NonNull
    @Override
    public String getJwksUri() {
        return jwksUri;
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

    @Nullable
    @Override
    public List<String> getScopesSupported() {
        return scopesSupported;
    }

    @NonNull
    @Override
    public List<String> getSubjectTypesSupported() {
        return subjectTypesSupported;
    }

    @NonNull
    @Override
    public String getTokenEndpoint() {
        return tokenEndpoint;
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

    @Nullable
    @Override
    public List<String> getDisplayValuesSupported() {
        return displayValuesSupported;
    }

    @Nullable
    @Override
    public List<String> getClaimTypesSupported() {
        return claimTypesSupported;
    }

    @Nullable
    @Override
    public String getUserinfoEndpoint() {
        return userinfoEndpoint;
    }

    @Nullable
    @Override
    public List<String> getResponseModesSupported() {
        return responseModesSupported;
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

    @Nullable
    @Override
    public String getRegistrationEndpoint() {
        return registrationEndpoint;
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

    @Nullable
    @Override
    public List<String> getClaimsLocalesSupported() {
        return claimsLocalesSupported;
    }

    @Nullable
    @Override
    public List<String> getUriLocalesSupported() {
        return uriLocalesSupported;
    }

    @Nullable
    @Override
    public Boolean getClaimsParameterSupported() {
        return claimsParameterSupported;
    }

    @Nullable
    @Override
    public List<String> getCodeChallengeMethodsSupported() {
        return codeChallengeMethodsSupported;
    }

    @Nullable
    @Override
    public String getIntrospectionEndpoint() {
        return introspectionEndpoint;
    }

    @Nullable
    @Override
    public List<String> getIntrospectionEndpointAuthMethodsSupported() {
        return introspectionEndpointAuthMethodsSupported;
    }

    @Nullable
    @Override
    public String getRevocationEndpoint() {
        return revocationEndpoint;
    }

    @Nullable
    @Override
    public List<String> getRevocationEndpointAuthMethodsSupported() {
        return revocationEndpointAuthMethodsSupported;
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

    @Nullable
    @Override
    public String getOpPolicyUri() {
        return opPolicyUri;
    }

    @Nullable
    @Override
    public String getOpTosUri() {
        return opTosUri;
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

    @Nullable
    @Override
    public List<String> getRequestObjectEncryptionEncValuesSupported() {
        return requestObjectEncryptionEncValuesSupported;
    }

    /**
     *
     * @return Creates a Builder.
     */
    @NonNull
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder.
     */
    public static class Builder {
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
            return new DefaultOpenIdProviderMetadata(authorizationEndpoint,
                idTokenSigningAlgValuesSupported,
                issuer,
                jwksUri,
                acrValuesSupported,
                responseTypesSupported,
                responseModesSupported,
                scopesSupported,
                grantTypesSupported,
                subjectTypesSupported,
                tokenEndpoint,
                tokenEndpointAuthMethodsSupported,
                userinfoEndpoint,
                registrationEndpoint,
                claimsSupported,
                codeChallengeMethodsSupported,
                introspectionEndpoint,
                introspectionEndpointAuthMethodsSupported,
                revocationEndpoint,
                revocationEndpointAuthMethodsSupported,
                endSessionEndpoint,
                requestParameterSupported,
                requestUriParameterSupported,
                requireRequestUriRegistration,
                requestObjectSigningAlgValuesSupported,
                serviceDocumentation,
                idTokenEncryptionEncValuesSupported,
                displayValuesSupported,
                claimTypesSupported,
                claimsParameterSupported,
                opTosUri,
                opPolicyUri,
                uriLocalesSupported,
                claimsLocalesSupported,
                userinfoEncryptionAlgValuesSupported,
                userinfoEncryptionEncValuesSupported,
                tokenEndpointAuthSigningAlgValuesSupported,
                requestObjectEncryptionAlgValuesSupported,
                requestObjectEncryptionEncValuesSupported,
                checkSessionIframe);
        }
    }
}
