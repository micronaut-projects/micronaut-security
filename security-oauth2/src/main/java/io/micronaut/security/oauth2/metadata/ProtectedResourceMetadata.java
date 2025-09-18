/*
 * Copyright 2017-2025 original authors
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
package io.micronaut.security.oauth2.metadata;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.serde.annotation.Serdeable;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Protected Resource Metadata as defined in RFC9728.
 * <a href="https://datatracker.ietf.org/doc/html/rfc9728#Terminology">Protected Resource Metadata Terminology</a>
 * @param resource The protected resource's resource identifier, which is a URL that uses the https scheme and has no fragment component.
 * @param authorizationServers JSON array containing a list of OAuth authorization server issuer identifiers.
 * @param jwksUri URL of the protected resource's JSON Web Key (JWK) Set [JWK] document.
 * @param scopesSupported JSON array containing a list of scope values.
 * @param bearerMethodsSupported JSON array containing a list of the supported methods of sending an OAuth 2.0 bearer token.
 * @param resourceSigningAlgValuesSupported  JSON array containing a list of the JWS [JWS] signing algorithms (alg values).
 * @param resourceName Human-readable name of the protected resource intended for display to the end user.
 * @param resourceDocumentation URL of a page containing human-readable information that developers might want or need to know when using the protected resource.
 * @param resourcePolicyUri URL of a page containing human-readable information about the protected resource's requirements on how the client can use the data provided by the protected resource.
 * @param resourceTosUri URL of a page containing human-readable information about the protected resource's terms of service.
 * @param tlsClientCertificateBoundAccessTokens Boolean value indicating protected resource support for mutual-TLS client certificate-bound access tokens.
 * @param authorizationDetailsTypesSupported JSON array containing a list of the authorization details type values supported by the resource server when the authorization_details request parameter [RFC9396] is used.
 * @param dpopSigningAlgValuesSupported SON array containing a list of the JWS alg values (from the "JSON Web Signature and Encryption Algorithms" registry [IANA.JOSE]) supported by the resource server for validating Demonstrating Proof of Possession (DPoP) proof JWTs [RFC9449].
 * @param dpopBoundAccessTokensRequired Boolean value specifying whether the protected resource always requires the use of DPoP-bound access tokens [RFC9449].
 */
@Serdeable
@Experimental
public record ProtectedResourceMetadata(
    @NonNull
    String resource,

    @JsonProperty("authorization_servers")
    @Nullable
    List<String> authorizationServers,

    @JsonProperty("jwks_uri")
    @Nullable
    String jwksUri,

    @JsonProperty("scopes_supported")
    @Nullable
    List<String> scopesSupported,

    @JsonProperty("bearer_methods_supported")
    @Nullable
    List<String> bearerMethodsSupported,

    @JsonProperty("resource_signing_alg_values_supported")
    @Nullable
    List<String> resourceSigningAlgValuesSupported,

    @JsonProperty("resource_name")
    String resourceName,

    @JsonProperty("resource_documentation")
    @Nullable
    String resourceDocumentation,

    @JsonProperty("resource_policy_uri")
    @Nullable
    String resourcePolicyUri,

    @JsonProperty("resource_tos_uri")
    @Nullable
    String resourceTosUri,

    @JsonProperty("tls_client_certificate_bound_access_tokens")
    @Nullable
    Boolean tlsClientCertificateBoundAccessTokens,

    @JsonProperty("authorization_details_types_supported")
    @Nullable
    List<String> authorizationDetailsTypesSupported,

    @JsonProperty("dpop_signing_alg_values_supported")
    @Nullable
    List<String> dpopSigningAlgValuesSupported,

    @JsonProperty("dpop_bound_access_tokens_required")
    Boolean dpopBoundAccessTokensRequired
) {
    /**
     * Create a new builder.
     * @return A builder instance.
     */
    @NonNull
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link ProtectedResourceMetadata}.
     */
    public static final class Builder {
        private String resource;
        private List<String> authorizationServers;
        private String jwksUri;
        private List<String> scopesSupported;
        private List<String> bearerMethodsSupported;
        private List<String> resourceSigningAlgValuesSupported;
        private String resourceName;
        private String resourceDocumentation;
        private String resourcePolicyUri;
        private String resourceTosUri;
        private Boolean tlsClientCertificateBoundAccessTokens;
        private List<String> authorizationDetailsTypesSupported;
        private List<String> dpopSigningAlgValuesSupported;
        private Boolean dpopBoundAccessTokensRequired;

        @NonNull
        public Builder resource(@NonNull String resource) {
            this.resource = resource;
            return this;
        }

        @NonNull
        public Builder authorizationServers(@Nullable List<String> authorizationServers) {
            this.authorizationServers = authorizationServers;
            return this;
        }

        @NonNull
        public Builder authorizationServer(@NonNull String issuer) {
            if (this.authorizationServers == null) {
                this.authorizationServers = new ArrayList<>();
            }
            this.authorizationServers.add(issuer);
            return this;
        }

        @NonNull
        public Builder authorizationServer(@NonNull URL issuer) {
            return authorizationServer(issuer.toString());
        }

        @NonNull
        public Builder jwksUri(@Nullable String jwksUri) {
            this.jwksUri = jwksUri;
            return this;
        }

        @NonNull
        public Builder scopesSupported(@Nullable List<String> scopesSupported) {
            this.scopesSupported = scopesSupported;
            return this;
        }

        @NonNull
        public Builder bearerMethodsSupported(@Nullable List<String> bearerMethodsSupported) {
            this.bearerMethodsSupported = bearerMethodsSupported;
            return this;
        }

        @NonNull
        public Builder resourceSigningAlgValuesSupported(@Nullable List<String> resourceSigningAlgValuesSupported) {
            this.resourceSigningAlgValuesSupported = resourceSigningAlgValuesSupported;
            return this;
        }

        @NonNull
        public Builder resourceName(String resourceName) {
            this.resourceName = resourceName;
            return this;
        }

        @NonNull
        public Builder resourceDocumentation(@Nullable String resourceDocumentation) {
            this.resourceDocumentation = resourceDocumentation;
            return this;
        }

        @NonNull
        public Builder resourcePolicyUri(@Nullable String resourcePolicyUri) {
            this.resourcePolicyUri = resourcePolicyUri;
            return this;
        }

        @NonNull
        public Builder resourceTosUri(@Nullable String resourceTosUri) {
            this.resourceTosUri = resourceTosUri;
            return this;
        }

        @NonNull
        public Builder tlsClientCertificateBoundAccessTokens(@Nullable Boolean tlsClientCertificateBoundAccessTokens) {
            this.tlsClientCertificateBoundAccessTokens = tlsClientCertificateBoundAccessTokens;
            return this;
        }

        @NonNull
        public Builder authorizationDetailsTypesSupported(@Nullable List<String> authorizationDetailsTypesSupported) {
            this.authorizationDetailsTypesSupported = authorizationDetailsTypesSupported;
            return this;
        }

        @NonNull
        public Builder dpopSigningAlgValuesSupported(@Nullable List<String> dpopSigningAlgValuesSupported) {
            this.dpopSigningAlgValuesSupported = dpopSigningAlgValuesSupported;
            return this;
        }

        @NonNull
        public Builder dpopBoundAccessTokensRequired(Boolean dpopBoundAccessTokensRequired) {
            this.dpopBoundAccessTokensRequired = dpopBoundAccessTokensRequired;
            return this;
        }

        /**
         * Build the {@link ProtectedResourceMetadata} instance.
         * @return a new {@link ProtectedResourceMetadata}
         */
        @NonNull
        public ProtectedResourceMetadata build() {
            Objects.requireNonNull(resource, "resource must not be null");
            return new ProtectedResourceMetadata(
                resource,
                authorizationServers,
                jwksUri,
                scopesSupported,
                bearerMethodsSupported,
                resourceSigningAlgValuesSupported,
                resourceName,
                resourceDocumentation,
                resourcePolicyUri,
                resourceTosUri,
                tlsClientCertificateBoundAccessTokens,
                authorizationDetailsTypesSupported,
                dpopSigningAlgValuesSupported,
                dpopBoundAccessTokensRequired
            );
        }
    }
}
