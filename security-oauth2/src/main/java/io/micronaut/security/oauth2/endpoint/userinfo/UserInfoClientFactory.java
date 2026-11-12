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
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.DisabledBeanException;
import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
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
import io.micronaut.security.utils.NoRedirectHttpClientConfiguration;
import jakarta.inject.Singleton;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

@Requires(beans = HttpClientConfiguration.class)
@Factory
@Internal
final class UserInfoClientFactory {
    private final BeanContext beanContext;
    private final HttpClientConfiguration httpClientConfiguration;
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
        this.qualifyUsername = openIdConfiguration.getQualifyUsernameWithProvider()
            .orElseGet(() -> oauthClientConfigurations.stream()
                .filter(OauthClientConfiguration::isEnabled)
                .filter(c -> c.getGrantType() != GrantType.CLIENT_CREDENTIALS)
                .count() > 1);
    }

    @EachBean(OpenIdProviderMetadata.class)
    @Prototype
    UserInfoClientTokenValidatorConfiguration createUserInfoClient(OpenIdProviderMetadata metadata) {
        String userInfoEndpoint = userInfoEndpointViaConfiguration(metadata.getName());
        if (StringUtils.isEmpty(userInfoEndpoint)) {
            userInfoEndpoint = metadata.getUserinfoEndpoint();
        }
        return createUserInfoClientWithUrl(userInfoEndpoint, metadata.getName());
    }

    @EachBean(UserInfoClientTokenValidatorConfiguration.class)
    @Singleton
    UserInfoClientTokenValidator createUserInfoClient(UserInfoClientTokenValidatorConfiguration config) {
        try {
            HttpClient httpClient = beanContext.createBean(HttpClient.class, new URL(config.baseUrl()), httpClientConfiguration);
            return new UserInfoClientTokenValidator(config.name(), httpClient, config.path(), qualifyUsername);
        } catch (MalformedURLException e) {
            throw new DisabledBeanException("Malformed URL Exception for UserInfo endpoint " + config.baseUrl() + " for " + config.getName());
        }
    }

    @Nullable
    private String userInfoEndpointViaConfiguration(String nameQualifier) {
        return beanContext.findBean(OpenIdClientConfiguration.class, Qualifiers.byName(nameQualifier))
            .flatMap(OpenIdClientConfiguration::getUserInfo)
            .flatMap(EndpointConfiguration::getUrl)
            .orElse(null);
    }

    @NonNull
    private UserInfoClientTokenValidatorConfiguration createUserInfoClientWithUrl(@Nullable String userInfoEndpoint,
                                                                                  @NonNull String name) {
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
                .build();
        } catch (MalformedURLException e) {
            throw new DisabledBeanException("Malformed URL Exception for UserInfo endpoint " + userInfoEndpoint + " for " + name);
        }
    }
}
