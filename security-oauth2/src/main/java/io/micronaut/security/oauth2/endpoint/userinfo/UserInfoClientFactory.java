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
import io.micronaut.context.BeanProvider;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.DisabledBeanException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.core.util.SupplierUtil;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;
import java.util.function.Supplier;

@Requires(beans = HttpClientConfiguration.class)
@Factory
@Internal
final class UserInfoClientFactory {
    private static final Logger LOG = LoggerFactory.getLogger(UserInfoClientFactory.class);
    private final BeanContext beanContext;
    private final HttpClientConfiguration httpClientConfiguration;

    UserInfoClientFactory(BeanContext beanContext,
                          HttpClientConfiguration httpClientConfiguration) {
        this.beanContext = beanContext;
        this.httpClientConfiguration = httpClientConfiguration;
    }

    /**
     * Creates a {@link UserInfoClientTokenValidator} for an OpenID provider. The UserInfo endpoint is resolved lazily
     * (on first token validation) so that the validator can be created even if the OpenID provider metadata could not be
     * fetched yet.
     *
     * @param openIdClientConfiguration The OpenID client configuration
     * @param openIdProviderMetadata The OpenID provider metadata
     * @return The token validator
     */
    @EachBean(OpenIdProviderMetadata.class)
    @Singleton
    UserInfoClientTokenValidator createUserInfoClient(@Parameter @Nullable OpenIdClientConfiguration openIdClientConfiguration,
                                                      @Parameter BeanProvider<OpenIdProviderMetadata> openIdProviderMetadata) {
        String name = openIdClientConfiguration != null ? openIdClientConfiguration.getName() : openIdProviderMetadata.get().getName();
        Supplier<OpenIdProviderMetadata> metadata = SupplierUtil.memoized(openIdProviderMetadata::get);
        String configuredUserInfoEndpoint = openIdClientConfiguration == null
            ? null
            : openIdClientConfiguration.getUserInfo().flatMap(EndpointConfiguration::getUrl).orElse(null);
        return new UserInfoClientTokenValidator(name, () -> {
            String userInfoEndpoint = StringUtils.isEmpty(configuredUserInfoEndpoint)
                ? metadata.get().getUserinfoEndpoint()
                : configuredUserInfoEndpoint;
            if (StringUtils.isEmpty(userInfoEndpoint)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("UserInfo endpoint not set for {}", name);
                }
                return Optional.empty();
            }
            return Optional.of(endpoint(createUserInfoClientWithUrl(userInfoEndpoint, name)));
        });
    }

    @EachBean(UserInfoClientTokenValidatorConfiguration.class)
    @Singleton
    UserInfoClientTokenValidator createUserInfoClient(UserInfoClientTokenValidatorConfiguration config) {
        return new UserInfoClientTokenValidator(config.name(), endpoint(config));
    }

    private UserInfoClientTokenValidator.Endpoint endpoint(@NonNull UserInfoClientTokenValidatorConfiguration config) {
        try {
            HttpClient httpClient = beanContext.createBean(HttpClient.class, new URL(config.baseUrl()), httpClientConfiguration);
            return new UserInfoClientTokenValidator.Endpoint(httpClient, config.path());
        } catch (MalformedURLException e) {
            throw new DisabledBeanException("Malformed URL Exception for UserInfo endpoint " + config.baseUrl() + " for " + config.getName());
        }
    }

    @NonNull
    private static UserInfoClientTokenValidatorConfiguration createUserInfoClientWithUrl(@NonNull String userInfoEndpoint,
                                                                                         @NonNull String name) {
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
