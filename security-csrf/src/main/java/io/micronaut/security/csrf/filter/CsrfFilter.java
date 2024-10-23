/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.csrf.filter;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.order.Ordered;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.*;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.http.filter.FilterPatternStyle;
import io.micronaut.http.filter.ServerFilterPhase;
import io.micronaut.http.server.exceptions.ExceptionHandler;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthorizationException;
import io.micronaut.security.csrf.resolver.CsrfTokenResolver;
import io.micronaut.security.csrf.resolver.ReactiveCsrfTokenResolver;
import io.micronaut.security.csrf.validator.CsrfTokenValidator;
import io.micronaut.security.filters.SecurityFilter;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;

/**
 * {@link RequestFilter} which validates CSRF tokens and rejects a request if the token is invalid.
 * Which requests are intercepted can be controlled via {@link io.micronaut.security.csrf.CsrfConfiguration}.
 * @author Sergio del Amo
 * @since 4.11.0
 */
@Internal
@Requires(property = CsrfFilterConfigurationProperties.PREFIX + ".enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Requires(classes = { ExceptionHandler.class, HttpRequest.class })
@Requires(beans = { CsrfTokenValidator.class })
@ServerFilter(patternStyle = FilterPatternStyle.REGEX,
        value = "${" + CsrfFilterConfigurationProperties.PREFIX + ".regex-pattern:" + CsrfFilterConfigurationProperties.DEFAULT_REGEX_PATTERN + "}")
final class CsrfFilter implements Ordered {
    private static final Logger LOG = LoggerFactory.getLogger(CsrfFilter.class);
    private final List<ReactiveCsrfTokenResolver<HttpRequest<?>>> reactiveCsrfTokenResolvers;
    private final List<CsrfTokenResolver<HttpRequest<?>>> csrfTokenResolvers;
    private final CsrfTokenValidator<HttpRequest<?>> csrfTokenValidator;
    private final ExceptionHandler<AuthorizationException, MutableHttpResponse<?>> exceptionHandler;
    private final CsrfFilterConfiguration csrfFilterConfiguration;

    CsrfFilter(CsrfFilterConfiguration csrfFilterConfiguration,
               List<ReactiveCsrfTokenResolver<HttpRequest<?>>> reactiveCsrfTokenResolvers,
               List<CsrfTokenResolver<HttpRequest<?>>> csrfTokenResolvers,
               CsrfTokenValidator<HttpRequest<?>> csrfTokenValidator,
               ExceptionHandler<AuthorizationException, MutableHttpResponse<?>> exceptionHandler) {
        this.csrfTokenResolvers = csrfTokenResolvers;
        this.reactiveCsrfTokenResolvers = reactiveCsrfTokenResolvers.isEmpty()
                ? reactiveCsrfTokenResolvers
                : ReactiveCsrfTokenResolver.of(csrfTokenResolvers, reactiveCsrfTokenResolvers);
        this.csrfTokenValidator = csrfTokenValidator;
        this.exceptionHandler = exceptionHandler;
        this.csrfFilterConfiguration = csrfFilterConfiguration;
    }

    @RequestFilter
    @Nullable
    public Publisher<Optional<MutableHttpResponse<?>>> csrfFilter(@NonNull HttpRequest<?> request) {
        if (!shouldTheFilterProcessTheRequestAccordingToTheHttpMethod(request)) {
            return proceedRequest();
        }
        if (!shouldTheFilterProcessTheRequestAccordingToTheContentType(request)) {
            return proceedRequest();
        }
        return reactiveCsrfTokenResolvers.isEmpty()
                ? imperativeFilter(request)
                : reactiveFilter(request);
    }

    private static Publisher<Optional<MutableHttpResponse<?>>> proceedRequest() {
        return Mono.just(Optional.empty());
    }

    private Publisher<Optional<MutableHttpResponse<?>>> reactiveFilter(HttpRequest<?> request) {
        return Flux.fromIterable(this.reactiveCsrfTokenResolvers)
                .concatMap(resolver -> Mono.from(resolver.resolveToken(request))
                        .filter(csrfToken -> {
                            LOG.debug("CSRF Token resolved");
                            if (csrfTokenValidator.validateCsrfToken(request, csrfToken)) {
                                return true;
                            } else {
                                LOG.debug("CSRF Token validation failed");
                                return false;
                            }
                        }))
                .next()
                .flatMap(validToken -> Mono.from(proceedRequest()))
                .switchIfEmpty(Mono.defer(() -> {
                    LOG.debug("Request rejected by the CsrfFilter");
                    return Mono.from(reactiveUnauthorized(request));
                }));
    }
    
    private Publisher<Optional<MutableHttpResponse<?>>> imperativeFilter(HttpRequest<?> request) {
        String csrfToken = resolveCsrfToken(request);
        if (csrfToken == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Request rejected by the {} because no CSRF Token found", this.getClass().getSimpleName());
            }
            return reactiveUnauthorized(request);
        }
        if (csrfTokenValidator.validateCsrfToken(request, csrfToken)) {
            return proceedRequest();
        }
        LOG.debug("Request rejected by the CSRF Filter because the CSRF Token validation failed");
        return reactiveUnauthorized(request);
    }

    private boolean shouldTheFilterProcessTheRequestAccordingToTheContentType(@NonNull HttpRequest<?> request) {
        final MediaType contentType = request.getContentType().orElse(null);
        if (contentType != null && csrfFilterConfiguration.getContentTypes().stream().noneMatch(method -> method.equals(contentType))) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Request {} {} with content type {} is not processed by the CSRF filter. CSRF filter only processes Content Types: {}",
                        request.getMethod(),
                        request.getPath(),
                        contentType,
                        csrfFilterConfiguration.getContentTypes().stream().map(MediaType::toString).toList());
            }
            return false;
        }
        return true;
    }

    private boolean shouldTheFilterProcessTheRequestAccordingToTheHttpMethod(@NonNull HttpRequest<?> request) {
        if (csrfFilterConfiguration.getMethods().stream().noneMatch(method -> method.equals(request.getMethod()))) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Request {} {} not processed by the CSRF filter. CSRF filter only processes HTTP Methods: {}",
                        request.getMethod(),
                        request.getPath(),
                        csrfFilterConfiguration.getMethods().stream().map(HttpMethod::name).toList());
            }
            return false;
        }
        return true;
    }

    @Nullable
    private String resolveCsrfToken(@NonNull HttpRequest<?> request) {
        for (CsrfTokenResolver<HttpRequest<?>> tokenResolver : csrfTokenResolvers) {
            Optional<String> tokenOptional = tokenResolver.resolveToken(request);
            if (tokenOptional.isPresent()) {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("CSRF token resolved via {}", tokenResolver.getClass().getSimpleName());
                }
                return tokenOptional.get();
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.trace("No CSRF token found in request");
        }
        return null;
    }

    @NonNull
    private Publisher<Optional<MutableHttpResponse<?>>> reactiveUnauthorized(@NonNull HttpRequest<?> request) {
        return Mono.just(Optional.of(unauthorized(request)));
    }

    @NonNull
    private MutableHttpResponse<?> unauthorized(@NonNull HttpRequest<?> request) {
        Authentication authentication = request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class)
                .orElse(null);
        return exceptionHandler.handle(request,
                new AuthorizationException(authentication));
    }

    @Override
    public int getOrder() {
        return ServerFilterPhase.SECURITY.order() + 100; // after {@link SecurityFilter}
    }
}
