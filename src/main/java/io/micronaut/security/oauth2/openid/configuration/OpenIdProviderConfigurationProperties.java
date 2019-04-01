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

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;

import javax.annotation.Nullable;
import java.util.List;

/**
 * {@link io.micronaut.context.annotation.ConfigurationProperties} implementation of {@link OpenIdProviderConfiguration}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@ConfigurationProperties(OpenIdProviderConfigurationProperties.PREFIX)
public class OpenIdProviderConfigurationProperties implements OpenIdProviderConfiguration {
    public static final String PREFIX = OauthConfigurationProperties.PREFIX + ".openid";

    private String openidIssuer;
    private List<String> scopesSupported;
    private List<String> responseTypesSupported;
    private List<String> subjectTypesSupported;
    private List<String> idTokenEncryptionEncValuesSupported;
    private List<String> requestObjectSigningAlgValuesSupported;
    private String jwksUri;

    @Nullable
    @Override
    public String getIssuer() {
        return openidIssuer;
    }

    /**
     *
     * @param issuer URL using the https scheme with no query or fragment component that the Open ID Provider asserts as its Issuer Identifier.
     */
    public void setIssuer(@Nullable String issuer) {
        this.openidIssuer = issuer;
    }

    /**
     *
     * @param scopesSupported List of the OAuth 2.0 [RFC6749] scope values that this server supports.
     */
    public void setScopesSupported(@Nullable List<String> scopesSupported) {
        this.scopesSupported = scopesSupported;
    }

    /**
     *
     * @param responseTypesSupported List of the OAuth 2.0 response_type values that this Open ID Provider supports.
     */
    public void setResponseTypesSupported(@Nullable List<String> responseTypesSupported) {
        this.responseTypesSupported = responseTypesSupported;
    }

    /**
     *
     * @param subjectTypesSupported List of the Subject Identifier types that this OP supports.
     */
    public void setSubjectTypesSupported(@Nullable List<String> subjectTypesSupported) {
        this.subjectTypesSupported = subjectTypesSupported;
    }

    /**
     *
     * @param idTokenEncryptionEncValuesSupported List of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT.
     */
    public void setIdTokenEncryptionEncValuesSupported(@Nullable List<String> idTokenEncryptionEncValuesSupported) {
        this.idTokenEncryptionEncValuesSupported = idTokenEncryptionEncValuesSupported;
    }

    /**
     *
     * @param requestObjectSigningAlgValuesSupported List of the JWS signing algorithms (alg values) supported by the OP for Request Objects.
     */
    public void setRequestObjectSigningAlgValuesSupported(@Nullable List<String> requestObjectSigningAlgValuesSupported) {
        this.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported;
    }

    @Nullable
    @Override
    public List<String> getScopesSupported() {
        return scopesSupported;
    }

    @Nullable
    @Override
    public List<String> getResponseTypesSupported() {
        return responseTypesSupported;
    }

    @Nullable
    @Override
    public List<String> getSubjectTypesSupported() {
        return subjectTypesSupported;
    }

    @Nullable
    @Override
    public List<String> getIdTokenEncryptionEncValuesSupported() {
        return idTokenEncryptionEncValuesSupported;
    }

    @Nullable
    @Override
    public List<String> getRequestObjectSigningAlgValuesSupported() {
        return requestObjectSigningAlgValuesSupported;
    }

    @Nullable
    @Override
    public String getJwksUri() {
        return jwksUri;
    }

    /**
     * Sets the JWKS uri.
     * @param jwksUri JWKS uri.
     */
    public void setJwksUri(@Nullable String jwksUri) {
        this.jwksUri = jwksUri;
    }
}
