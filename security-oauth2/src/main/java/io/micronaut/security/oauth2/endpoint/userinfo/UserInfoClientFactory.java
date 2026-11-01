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
package io.micronaut.security.oauth2.endpoint.userinfo;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Prototype;
import io.micronaut.context.exceptions.DisabledBeanException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.SupplierUtil;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.grants.GrantType;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.UserInfoEndpointConfiguration;
import io.micronaut.security.token.IssuerUtils;
import io.micronaut.security.utils.NoRedirectHttpClientConfiguration;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Factory
@Internal
final class UserInfoClientFactory {
    private static final Logger LOG = LoggerFactory.getLogger(UserInfoClientFactory.class);
    private final BeanContext beanContext;
    private final HttpClientConfiguration httpClientConfiguration;
    private final List<OauthClientConfiguration> oauthClientConfigurations;
    private final Supplier<Collection<UserInfoClientTokenValidator>> userInfoClientTokenValidators;
    private final Supplier<Boolean> soleUserInfoClientTokenValidator;
    private final boolean qualifyUsername;

    /**
     * @param beanContext Bean context
     * @param httpClientConfiguration HTTP client configuration
     * @param oauthClientConfigurations OAuth 2.0 client configurations
     * @param openIdConfiguration OpenID configuration. If {@link OpenIdConfiguration#getQualifyUsernameWithProvider()}
     *                            is empty, usernames are qualified when more than one enabled client which can
     *                            authenticate users is configured.
     */
    UserInfoClientFactory(BeanContext beanContext,
                          HttpClientConfiguration httpClientConfiguration,
                          List<OauthClientConfiguration> oauthClientConfigurations,
                          OpenIdConfiguration openIdConfiguration) {
        this.beanContext = beanContext;
        // the UserInfo client never follows redirects: the bearer token must only be sent to the configured endpoint
        this.httpClientConfiguration = new NoRedirectHttpClientConfiguration(httpClientConfiguration);
        this.oauthClientConfigurations = oauthClientConfigurations;
        this.userInfoClientTokenValidators = SupplierUtil.memoized(() -> beanContext.getBeansOfType(UserInfoClientTokenValidator.class));
        // The implicit allowance to receive tokens which cannot be attributed to a provider is decided by the configured
        // trust relationships, never by which providers happened to be reachable at startup: a provider whose discovery
        // failed has no validator, and that failure must not turn the remaining provider into the "sole" one. The
        // providers are identified by name, combining the configured OpenID clients with the instantiated validators
        // (which include manually registered configurations), so a configured client without a validator and a
        // validator without a configured client are two providers, not one.
        Set<String> configuredOpenIdClients = oauthClientConfigurations.stream()
            .filter(OauthClientConfiguration::isEnabled)
            .filter(c -> c.getOpenid().isPresent())
            .map(OauthClientConfiguration::getName)
            .collect(Collectors.toSet());
        this.soleUserInfoClientTokenValidator = SupplierUtil.memoized(() -> {
            Set<String> providers = new HashSet<>(configuredOpenIdClients);
            for (UserInfoClientTokenValidator validator : userInfoClientTokenValidators.get()) {
                providers.add(validator.getName());
            }
            return providers.size() == 1;
        });
        this.qualifyUsername = openIdConfiguration.getQualifyUsernameWithProvider()
            .orElseGet(() -> oauthClientConfigurations.stream()
                .filter(OauthClientConfiguration::isEnabled)
                .filter(c -> c.getGrantType() != GrantType.CLIENT_CREDENTIALS)
                .count() > 1);
    }

    @EachBean(OpenIdProviderMetadata.class)
    @Prototype
    UserInfoClientTokenValidatorConfiguration createUserInfoClient(OpenIdProviderMetadata metadata) {
        Optional<EndpointConfiguration> userInfoConfiguration = userInfoConfiguration(metadata.getName());
        String userInfoEndpoint = userInfoConfiguration.flatMap(EndpointConfiguration::getUrl).orElse(null);
        if (StringUtils.isEmpty(userInfoEndpoint)) {
            userInfoEndpoint = metadata.getUserinfoEndpoint();
        }
        Boolean validateOpaqueTokens = userInfoConfiguration
            .filter(UserInfoEndpointConfiguration.class::isInstance)
            .map(UserInfoEndpointConfiguration.class::cast)
            .flatMap(UserInfoEndpointConfiguration::getValidateOpaqueTokens)
            .orElse(null);
        String issuer = issuer(metadata);
        if (StringUtils.isEmpty(issuer) && LOG.isWarnEnabled()) {
            LOG.warn("The UserInfo endpoint of the OpenID client [{}] is not bound to an issuer because neither 'openid.issuer' is configured nor the provider metadata asserts one. JWTs are treated like opaque tokens: their 'iss' claim is not checked before they are sent to the endpoint. Set 'micronaut.security.oauth2.clients.{}.openid.issuer' or 'openid.issuer-identifier'.", metadata.getName(), metadata.getName());
        }
        return createUserInfoClientWithUrl(userInfoEndpoint, metadata.getName(), issuer, validateOpaqueTokens);
    }

    @EachBean(UserInfoClientTokenValidatorConfiguration.class)
    @Singleton
    UserInfoClientTokenValidator createUserInfoClient(UserInfoClientTokenValidatorConfiguration config) {
        try {
            HttpClient httpClient = beanContext.createBean(HttpClient.class, new URL(config.baseUrl()), httpClientConfiguration);
            return new UserInfoClientTokenValidator(config, httpClient, issuerSharedWithAnotherProvider(config.name(), config.issuer()), soleUserInfoClientTokenValidator, qualifyUsername);
        } catch (MalformedURLException e) {
            throw new DisabledBeanException("Malformed URL Exception for UserInfo endpoint " + config.baseUrl() + " for " + config.getName());
        }
    }

    /**
     * The issuer expected in the {@code iss} claim of the tokens of the provider: {@link OpenIdClientConfiguration#getIssuerIdentifier()}
     * (which defaults to {@link OpenIdClientConfiguration#getIssuer()}). The issuer announced by the provider's discovery document is only
     * used when none is configured, because a provider is not trusted to attribute tokens: it could announce the issuer of another provider.
     */
    @Nullable
    private String issuer(OpenIdProviderMetadata metadata) {
        return beanContext.findBean(OpenIdClientConfiguration.class, Qualifiers.byName(metadata.getName()))
            .flatMap(OpenIdClientConfiguration::getIssuerIdentifier)
            .filter(StringUtils::isNotEmpty)
            .orElse(metadata.getIssuer());
    }

    /**
     * Whether another provider expects the same issuer, in which case a JWT of that issuer cannot be attributed to exactly one
     * provider (for example two Oracle IDCS tenants, which both issue tokens with the provider wide issuer but have distinct UserInfo
     * endpoints). The other providers are looked up both in the configured OAuth 2.0 clients, so that a provider whose discovery failed
     * is still accounted for, and in the instantiated validators, whose issuer may come from the discovery document.
     *
     * @param name Provider name
     * @param issuer Expected issuer of the provider
     * @return A memoized supplier which is {@code true} if another provider expects an equivalent issuer. The first evaluation logs a warning naming those providers.
     */
    @NonNull
    private Supplier<Boolean> issuerSharedWithAnotherProvider(@NonNull String name, @Nullable String issuer) {
        if (issuer == null) {
            return () -> false;
        }
        return SupplierUtil.memoized(() -> {
            Set<String> others = new TreeSet<>();
            for (OauthClientConfiguration clientConfiguration : oauthClientConfigurations) {
                if (clientConfiguration.isEnabled() && !clientConfiguration.getName().equals(name)) {
                    clientConfiguration.getOpenid()
                        .flatMap(OpenIdClientConfiguration::getIssuerIdentifier)
                        .filter(other -> IssuerUtils.equivalent(issuer, other))
                        .ifPresent(other -> others.add(clientConfiguration.getName()));
                }
            }
            for (UserInfoClientTokenValidator validator : userInfoClientTokenValidators.get()) {
                if (!validator.getName().equals(name) && IssuerUtils.equivalent(issuer, validator.issuer())) {
                    others.add(validator.getName());
                }
            }
            if (!others.isEmpty() && LOG.isWarnEnabled()) {
                LOG.warn("The OpenID client [{}] expects the same issuer [{}] as the OpenID clients {}. A JWT of that issuer cannot be attributed to a single provider, so it is only sent to the UserInfo endpoint of the clients which set 'micronaut.security.oauth2.clients.*.openid.user-info.validate-opaque-tokens' to true.", name, issuer, others);
            }
            return !others.isEmpty();
        });
    }

    @NonNull
    private Optional<EndpointConfiguration> userInfoConfiguration(String nameQualifier) {
        return beanContext.findBean(OpenIdClientConfiguration.class, Qualifiers.byName(nameQualifier))
            .flatMap(OpenIdClientConfiguration::getUserInfo);
    }

    @NonNull
    private UserInfoClientTokenValidatorConfiguration createUserInfoClientWithUrl(@Nullable String userInfoEndpoint,
                                                                                  @NonNull String name,
                                                                                  @Nullable String issuer,
                                                                                  @Nullable Boolean validateOpaqueTokens) {
        if (StringUtils.isEmpty(userInfoEndpoint)) {
            throw new DisabledBeanException("UserInfo endpoint not set for " + name);
        }
        try {
            URL url = new URL(userInfoEndpoint);
            String path = url.getPath();
            String baseUrl = url.toString().substring(0, url.toString().indexOf(path));
            return UserInfoClientTokenValidatorConfiguration.builder()
                .baseUrl(baseUrl)
                .name(name)
                .path(path)
                .issuer(StringUtils.isEmpty(issuer) ? null : issuer)
                .validateOpaqueTokens(validateOpaqueTokens)
                .build();
        } catch (MalformedURLException e) {
            throw new DisabledBeanException("Malformed URL Exception for UserInfo endpoint " + userInfoEndpoint + " for " + name);
        }
    }
}
