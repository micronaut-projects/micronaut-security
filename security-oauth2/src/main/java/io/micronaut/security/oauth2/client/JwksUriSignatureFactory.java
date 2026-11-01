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

import io.micronaut.context.BeanContext;
import io.micronaut.context.BeanProvider;
import io.micronaut.context.BeanRegistration;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.oauth2.client.condition.OauthClientEnabledCondition;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.token.jwt.nimbus.ReactiveJwksSignature;
import io.micronaut.security.token.jwt.signature.jwks.JwksClientConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import jakarta.inject.Named;

import java.util.concurrent.ExecutorService;

/**
 * Factory to create {@link ReactiveJwksSignature} beans for the {@link OpenIdProviderMetadata#getJwksUri()} of OpenID clients.
 * <p>
 * The beans are only created for the {@link io.micronaut.security.authentication.AuthenticationMode#IDTOKEN} authentication mode, where the
 * ID token issued by the provider is the request credential. In any other authentication mode, tokens signed by the provider's keys, such
 * as ID tokens issued to other clients, must not authenticate requests. The ID token obtained during the authorization code flow is
 * validated against the provider's JWKS independently of these beans. No bean is created for a disabled OAuth 2.0 client.
 * <p>
 * The key set of a provider is bound to the issuer of that provider (see {@link JwksSignatureConfiguration#getIssuer()}),
 * so that a token whose {@code iss} claim names one provider cannot be verified with the keys of another provider.
 *
 * @author Sergio del Amo
 * @since 1.3.0
 */
@Factory
@Internal
public class JwksUriSignatureFactory {

    private final BeanContext beanContext;

    /**
     * @param beanContext The bean context
     */
    public JwksUriSignatureFactory(BeanContext beanContext) {
        this.beanContext = beanContext;
    }

    /**
     * Creates a {@link JwksSignatureConfiguration} for the {@code jwks_uri} exposed via the OpenID configuration of the client.
     * The configuration is created for every enabled OpenID client, even if the OpenID configuration could not be fetched at startup,
     * so that an unreachable provider never leaves the application without signature configurations. The {@code jwks_uri} and the
     * issuer come from the provider metadata: the one already created at startup, or else one resolved on the blocking executor,
     * see {@link OpenIdProviderJwksSignatureConfiguration}.
     *
     * @param openIdClientConfiguration The OpenID client configuration
     * @param openIdProviderMetadata The open id provider metadata
     * @param executorService Executor used to resolve the provider metadata when it was not created at startup
     * @param jwksClientConfiguration JWKS client configuration, whose failure back-off bounds how often the provider metadata is requested after a failure
     * @return a {@link JwksSignatureConfiguration} pointed to the jwks_uri exposed via OpenID configuration and bound to the issuer of the OpenID client
     */
    @Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "idtoken")
    @Requires(condition = OauthClientEnabledCondition.class)
    @EachBean(OpenIdClientConfiguration.class)
    public JwksSignatureConfiguration createJwksSignatureConfiguration(@Parameter OpenIdClientConfiguration openIdClientConfiguration,
                                                                       @Parameter BeanProvider<DefaultOpenIdProviderMetadata> openIdProviderMetadata,
                                                                       @Named(TaskExecutors.BLOCKING) ExecutorService executorService,
                                                                       JwksClientConfiguration jwksClientConfiguration) {
        String name = openIdClientConfiguration.getName();
        return new OpenIdProviderJwksSignatureConfiguration(name,
            openIdClientConfiguration.getIssuerIdentifier().orElse(null),
            createdMetadata(name),
            openIdProviderMetadata,
            executorService,
            jwksClientConfiguration.getFailureBackoff());
    }

    /**
     * The provider metadata bean is created eagerly at startup. Looking it up among the created singletons, instead of
     * through the provider, never fetches the discovery document on the thread creating this configuration.
     *
     * @param name The OpenID client name
     * @return The provider metadata of the client if it has already been created, {@code null} otherwise
     */
    @Nullable
    private DefaultOpenIdProviderMetadata createdMetadata(@NonNull String name) {
        return beanContext.getActiveBeanRegistrations(DefaultOpenIdProviderMetadata.class).stream()
            .map(BeanRegistration::getBean)
            .filter(metadata -> name.equals(metadata.getName()))
            .findFirst()
            .orElse(null);
    }
}
