/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.token.cookie;

import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.env.Environment;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.cookie.CookieConfiguration;
import io.micronaut.http.cookie.SameSite;
import io.micronaut.security.authentication.CookieBasedAuthenticationModeCondition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

/**
 * Validates at startup the {@code cookie-same-site} setting of the access token and refresh token cookies.
 * An unrecognized value would otherwise be silently bound to {@code null} and the {@code SameSite} attribute omitted.
 * An empty value, which omits the {@code SameSite} attribute, is logged.
 *
 * @author Sergio del Amo
 * @since 5.6.0
 */
@Requires(classes = CookieConfiguration.class)
@Requires(condition = CookieBasedAuthenticationModeCondition.class)
@Context
@Internal
final class TokenCookieSameSiteValidator {

    private static final Logger LOG = LoggerFactory.getLogger(TokenCookieSameSiteValidator.class);

    private static final String COOKIE_SAME_SITE = ".cookie-same-site";

    private static final List<String> PROPERTIES = List.of(
        TokenCookieConfigurationProperties.PREFIX + COOKIE_SAME_SITE,
        RefreshTokenCookieConfigurationProperties.PREFIX + COOKIE_SAME_SITE
    );

    /**
     * @param environment The environment
     * @throws ConfigurationException if a same-site setting is not empty and it is not a {@link SameSite} value
     */
    TokenCookieSameSiteValidator(Environment environment) {
        for (String property : PROPERTIES) {
            if (environment.containsProperty(property)) {
                validate(property, environment.getProperty(property, String.class).orElse(null));
            }
        }
    }

    private static void validate(String property, String value) {
        if (!StringUtils.hasText(value)) {
            LOG.info("{} is empty. The cookie will be issued without the SameSite attribute.", property);
            return;
        }
        if (Arrays.stream(SameSite.values()).noneMatch(sameSite -> sameSite.name().equalsIgnoreCase(value))) {
            throw new ConfigurationException("Invalid value '" + value + "' for " + property
                + ". Allowed values: Strict, Lax or None. Use an empty value to omit the SameSite attribute.");
        }
    }
}
