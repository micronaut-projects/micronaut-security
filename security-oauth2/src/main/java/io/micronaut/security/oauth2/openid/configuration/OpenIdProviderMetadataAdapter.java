/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.openid.configuration;

import io.micronaut.security.oauth2.openid.endpoints.Endpoint;
import io.micronaut.security.oauth2.openid.endpoints.authorization.AuthorizationEndpoint;
import io.micronaut.security.oauth2.openid.endpoints.introspection.IntrospectionEndpoint;
import io.micronaut.security.oauth2.openid.endpoints.registration.RegistrationEndpoint;
import io.micronaut.security.oauth2.openid.endpoints.revocation.RevocationEndpoint;
import io.micronaut.security.oauth2.openid.endpoints.token.TokenEndpoint;
import io.micronaut.security.oauth2.openid.endpoints.userinfo.UserInfoEndpoint;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

/**
 * Creates an {@link OpenIdProviderMetadata} by merging together an existing {@link OpenIdProviderMetadata}, probably from a
 * fetched from remote identity provider, with the different endpoint configurations.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class OpenIdProviderMetadataAdapter implements OpenIdProviderMetadata {

    private OpenIdProviderMetadata openIdProviderMetadata;
    private OpenIdProviderConfiguration openIdProviderConfiguration;
    private AuthorizationEndpoint authorizationEndpoint;
    private IntrospectionEndpoint introspectionEndpoint;
    private RegistrationEndpoint registrationEndpoint;
    private RevocationEndpoint revocationEndpoint;
    private TokenEndpoint tokenEndpoint;
    private UserInfoEndpoint userInfoEndpoint;

    /**
     *
     * @param openIdProviderMetadata Open ID provider metadata
     * @param openIdProviderConfiguration Open ID Provider configuration
     * @param authorizationEndpoint Authorization endpoint configuration.
     * @param introspectionEndpoint Introspection endpoint configuration.
     * @param registrationEndpoint Registration endpoint configuration.
     * @param revocationEndpoint Revocation endpoint configuration.
     * @param tokenEndpoint Token endpoint configuration.
     * @param userInfoEndpoint User info endpoint configuration.
     */
    public OpenIdProviderMetadataAdapter(@Nullable OpenIdProviderMetadata openIdProviderMetadata,
                                         @Nonnull OpenIdProviderConfiguration openIdProviderConfiguration,
                                         @Nonnull AuthorizationEndpoint authorizationEndpoint,
                                         @Nonnull IntrospectionEndpoint introspectionEndpoint,
                                         @Nonnull RegistrationEndpoint registrationEndpoint,
                                         @Nonnull RevocationEndpoint revocationEndpoint,
                                         @Nonnull TokenEndpoint tokenEndpoint,
                                         @Nonnull UserInfoEndpoint userInfoEndpoint) {
        this.openIdProviderMetadata = openIdProviderMetadata;
        this.openIdProviderConfiguration = openIdProviderConfiguration;
        this.authorizationEndpoint = authorizationEndpoint;
        this.introspectionEndpoint = introspectionEndpoint;
        this.registrationEndpoint = registrationEndpoint;
        this.revocationEndpoint = revocationEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.userInfoEndpoint = userInfoEndpoint;
    }

    @Nonnull
    @Override
    public String getIssuer() {
        return Objects.requireNonNull(openIdProviderMetadata != null ? openIdProviderMetadata.getIssuer() : openIdProviderConfiguration.getIssuer());
    }

    @Nonnull
    @Override
    public String getAuthorizationEndpoint() {
        return getAuthorizationEndpointUrl();
    }

    @Nullable
    @Override
    public String getTokenEndpoint() {
        return getTokenEndpointUrl();
    }

    @Nullable
    @Override
    public String getUserinfoEndpoint() {
        return getUserinfoEndpointUrl();
    }

    @Nonnull
    @Override
    public String getJwksUri() {
        return Objects.requireNonNull(openIdProviderMetadata != null ? openIdProviderMetadata.getJwksUri() : openIdProviderConfiguration.getJwksUri());
    }

    @Nullable
    @Override
    public String getRegistrationEndpoint() {
        return getRegistrationEndpointUrl();
    }

    @Nullable
    @Override
    public List<String> getScopesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getScopesSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getResponseTypesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getResponseTypesSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getResponseModesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getResponseModesSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getGrantTypesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getGrantTypesSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getAcrValuesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getAcrValuesSupported() : null;
    }

    @Nonnull
    @Override
    public List<String> getSubjectTypesSupported() {
        return Objects.requireNonNull(openIdProviderMetadata != null ? openIdProviderMetadata.getSubjectTypesSupported() : openIdProviderConfiguration.getSubjectTypesSupported());
    }

    @Nonnull
    @Override
    public List<String> getIdTokenSigningAlgValuesSupported() {
        return Objects.requireNonNull(openIdProviderMetadata != null ? openIdProviderMetadata.getIdTokenSigningAlgValuesSupported() : openIdProviderConfiguration.getIdTokenEncryptionEncValuesSupported());
    }

    @Nullable
    @Override
    public List<String> getIdTokenEncryptionEncValuesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getIdTokenEncryptionEncValuesSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getUserInfoEncryptionAlgValuesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getUserInfoEncryptionAlgValuesSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getUserinfoEncryptionEncValuesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getUserinfoEncryptionEncValuesSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getRequestObjectSigningAlgValuesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getRequestObjectSigningAlgValuesSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getRequestObjectEncryptionAlgValuesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getRequestObjectEncryptionAlgValuesSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getRequestObjectEncryptionEncValuesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getRequestObjectEncryptionEncValuesSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getTokenEndpointAuthMethodsSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getTokenEndpointAuthMethodsSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getTokenEndpointAuthSigningAlgValuesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getTokenEndpointAuthSigningAlgValuesSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getDisplayValuesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getDisplayValuesSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getClaimTypesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getClaimTypesSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getClaimsSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getClaimsSupported() : null;
    }

    @Nullable
    @Override
    public String getServiceDocumentation() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getServiceDocumentation() : null;
    }

    @Nullable
    @Override
    public List<String> getClaimsLocalesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getClaimsLocalesSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getUriLocalesSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getUriLocalesSupported() : null;
    }

    @Nullable
    @Override
    public Boolean getClaimsParameterSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getClaimsParameterSupported() : null;
    }

    @Nullable
    @Override
    public Boolean getRequestParameterSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getRequestParameterSupported() : null;
    }

    @Nullable
    @Override
    public Boolean getRequestUriParameterSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getRequestUriParameterSupported() : null;
    }

    @Nullable
    @Override
    public Boolean getRequireRequestUriRegistration() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getRequireRequestUriRegistration() : null;
    }

    @Nullable
    @Override
    public String getOpPolicyUri() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getOpPolicyUri() : null;
    }

    @Nullable
    @Override
    public String getOpTosUri() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getOpTosUri() : null;
    }

    @Nullable
    @Override
    public List<String> getCodeChallengeMethodsSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getCodeChallengeMethodsSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getIntrospectionEndpointAuthMethodsSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getIntrospectionEndpointAuthMethodsSupported() : null;
    }

    @Nullable
    @Override
    public List<String> getRevocationEndpointAuthMethodsSupported() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getRevocationEndpointAuthMethodsSupported() : null;
    }

    @Nullable
    @Override
    public String getIntrospectionEndpoint() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getIntrospectionEndpoint() : null;
    }

    @Nullable
    @Override
    public String getRevocationEndpoint() {
        return openIdProviderMetadata != null ? openIdProviderMetadata.getRevocationEndpoint() : null;
    }

    /**
     *
     * @return resolved userinfo endpoint url
     */
    protected String getUserinfoEndpointUrl() {
        return resolveUrl(userInfoEndpoint, OpenIdProviderMetadata::getUserinfoEndpoint);
    }

    /**
     *
     * @return resolved token endpoint url
     */
    protected String getTokenEndpointUrl() {
        return resolveUrl(tokenEndpoint, OpenIdProviderMetadata::getTokenEndpoint);
    }

    /**
     *
     * @return resolved revocation endpoint url
     */
    protected String getRevocationEndpointUrl() {
        return resolveUrl(revocationEndpoint, OpenIdProviderMetadata::getRevocationEndpoint);
    }

    /**
     *
     * @return resolved registration endpoint url
     */
    protected String getRegistrationEndpointUrl() {
        return resolveUrl(registrationEndpoint, OpenIdProviderMetadata::getRegistrationEndpoint);
    }

    /**
     *
     * @return resolved introspection endpoint url
     */
    protected String getIntrospectionEndpointUrl() {
        return resolveUrl(introspectionEndpoint, OpenIdProviderMetadata::getIntrospectionEndpoint);
    }

    /**
     *
     * @return resolved authorization endpoint url
     */
    protected String getAuthorizationEndpointUrl() {
        return resolveUrl(authorizationEndpoint, OpenIdProviderMetadata::getAuthorizationEndpoint);
    }

    private String resolveUrl(Endpoint endpoint, Function<OpenIdProviderMetadata, String> urlProvider) {
        String endpointUrl = endpoint.getUrl();
        if (endpointUrl == null && openIdProviderMetadata != null) {
            endpointUrl = urlProvider.apply(openIdProviderMetadata);
        }
        return endpointUrl;
    }
}
