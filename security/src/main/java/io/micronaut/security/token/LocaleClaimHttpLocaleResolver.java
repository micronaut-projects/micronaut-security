/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.token;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.convert.ConversionService;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.server.util.locale.HttpAbstractLocaleResolver;
import io.micronaut.http.server.util.locale.HttpLocaleResolutionConfiguration;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.context.ServerRequestContextSecurityContextSupplier;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Resolves the HTTP locale from the OpenID Connect {@code locale} claim in the
 * current {@link Authentication}.
 *
 * @author Sergio del Amo
 * @since 5.2.1
 */
@Requires(classes = HttpRequest.class)
@Requires(beans = HttpLocaleResolutionConfiguration.class)
@Singleton
public class LocaleClaimHttpLocaleResolver extends HttpAbstractLocaleResolver {
    private static final int ORDER = HttpAbstractLocaleResolver.ORDER + 10;

    private final ConversionService conversionService;

    /**
     * Creates a locale resolver backed by the HTTP locale resolution configuration.
     *
     * @param httpLocaleResolutionConfiguration Locale resolution configuration
     * @param conversionService ConversionService
     */
    public LocaleClaimHttpLocaleResolver(HttpLocaleResolutionConfiguration httpLocaleResolutionConfiguration,
                                         ConversionService conversionService) {
        super(httpLocaleResolutionConfiguration);
        this.conversionService = conversionService;
    }

    /**
     * Resolves the locale from the authentication associated with the request.
     *
     * @param request The HTTP request
     * @return The resolved locale, or {@link Optional#empty()} if no authentication
     * or locale claim is present
     */
    @NonNull
    @Override
    public Optional<Locale> resolve(@NonNull HttpRequest<?> request) {
        return resolve(ServerRequestContextSecurityContextSupplier.getSecurityContext(request).getAuthentication());
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    private @NonNull Optional<@NonNull Locale> resolve(@Nullable Authentication authentication) {
        if (authentication == null) {
            return Optional.empty();
        }
        return resolve(authentication.getAttributes());
    }

    private @NonNull Optional<@NonNull Locale> resolve(@NonNull Map<String, Object> attributes) {
        Object claimValue = attributes.get(ProfileClaims.CLAIM_LOCALE);
        if (claimValue == null) {
            return Optional.empty();
        }
        return conversionService.convert(claimValue, Locale.class);
    }
}
