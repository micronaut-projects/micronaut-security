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
package io.micronaut.security.authentication;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaderValues;
import io.micronaut.http.HttpRequest;
import io.micronaut.runtime.ApplicationConfiguration;
import jakarta.inject.Singleton;

/**
 * {@link WwwAuthenticateChallengeProvider} implementation for basic auth authentication.
 * @since 4.14.0
 */
@Requires(classes = HttpRequest.class)
@Requires(beans = { ApplicationConfiguration.class, BasicAuthAuthenticationFetcher.class })
@Requires(property = BasicAuthAuthenticationConfiguration.PROPERTY_ENABLED, notEquals = StringUtils.FALSE)
@Requires(property = BasicAuthAuthenticationConfiguration.PROPERTY_WWW_AUTHENTICATE, notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Internal
@Singleton
class BasicAuthWwwAuthenticateChallengeProvider implements WwwAuthenticateChallengeProvider<HttpRequest<?>> {
    private static final String PARAM_REALM = "realm";
    private static final String PARAM_NAME_CHARSET = "charset";
    private static final String UTF_8 = "UTF-8";
    private final ApplicationConfiguration applicationConfiguration;

    BasicAuthWwwAuthenticateChallengeProvider(ApplicationConfiguration applicationConfiguration) {
        this.applicationConfiguration = applicationConfiguration;
    }

    @Override
    @NonNull
    public String getWwwAuthenticateChallenge(@Nullable HttpRequest<?> request) {
        WwwAuthenticateChallenge.Builder builder = WwwAuthenticateChallenge.builder()
            .authScheme(HttpHeaderValues.AUTHORIZATION_PREFIX_BASIC)
            .param(PARAM_NAME_CHARSET, UTF_8);
        applicationConfiguration.getName().ifPresent(name -> builder.param(PARAM_REALM, name));
        return builder.build().toString();
    }
}
