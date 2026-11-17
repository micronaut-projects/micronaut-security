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
import io.micronaut.core.order.Ordered;
import io.micronaut.core.util.PathMatcher;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.http.exceptions.ContentLengthExceededException;
import io.micronaut.http.filter.FilterPatternStyle;
import io.micronaut.http.filter.ServerFilterPhase;
import io.micronaut.http.server.exceptions.ExceptionHandler;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthorizationException;
import io.micronaut.security.csrf.resolver.CsrfTokenResolver;
import io.micronaut.security.csrf.resolver.FutureCsrfTokenResolver;
import io.micronaut.security.csrf.validator.CsrfTokenValidator;
import io.micronaut.security.context.ServerRequestContextSecurityContextSupplier;
import io.micronaut.web.router.RouteAttributes;
import io.micronaut.web.router.RouteMatch;
import io.micronaut.web.router.UriRouteMatch;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

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
    private static final CompletableFuture<@Nullable HttpResponse<?>> PROCEED = CompletableFuture.completedFuture(null);
    private final List<FutureCsrfTokenResolver<HttpRequest<?>>> futureCsrfTokenResolvers;
    private final List<CsrfTokenResolver<HttpRequest<?>>> csrfTokenResolvers;
    private final CsrfTokenValidator<HttpRequest<?>> csrfTokenValidator;
    private final ExceptionHandler<AuthorizationException, MutableHttpResponse<?>> exceptionHandler;
    private final CsrfFilterConfiguration csrfFilterConfiguration;

    CsrfFilter(CsrfFilterConfiguration csrfFilterConfiguration,
               List<FutureCsrfTokenResolver<HttpRequest<?>>> futureCsrfTokenResolvers,
               List<CsrfTokenResolver<HttpRequest<?>>> csrfTokenResolvers,
               CsrfTokenValidator<HttpRequest<?>> csrfTokenValidator,
               ExceptionHandler<AuthorizationException, MutableHttpResponse<?>> exceptionHandler) {
        this.csrfTokenResolvers = csrfTokenResolvers;
        this.futureCsrfTokenResolvers = futureCsrfTokenResolvers.isEmpty()
                ? futureCsrfTokenResolvers
                : FutureCsrfTokenResolver.of(csrfTokenResolvers, futureCsrfTokenResolvers);
        this.csrfTokenValidator = csrfTokenValidator;
        this.exceptionHandler = exceptionHandler;
        this.csrfFilterConfiguration = csrfFilterConfiguration;
    }

    @RequestFilter
    @Nullable
    public CompletableFuture<@Nullable HttpResponse<?>> csrfFilter(@NonNull HttpRequest<?> request) {
        if (!shouldTheFilterProcessTheRequestAccordingToTheUriMatch(request)) {
            return PROCEED;
        }
        if (!shouldTheFilterProcessTheRequestAccordingToTheHttpMethod(request)) {
            return PROCEED;
        }
        if (!shouldTheFilterProcessTheRequestAccordingToTheContentType(request)) {
            return PROCEED;
        }
        return futureCsrfTokenResolvers.isEmpty()
                ? imperativeFilter(request)
                : reactiveFilter(request);
    }

    boolean shouldTheFilterProcessTheRequestAccordingToTheUriMatch(HttpRequest<?> request) {
        try (RouteMatch<?> routeMatch = RouteAttributes.getRouteMatch(request).orElse(null)) {
            if (routeMatch instanceof UriRouteMatch<?, ?> uriRouteMatch) {
                return shouldTheFilterProcessTheRequestAccordingToTheUriMatch(uriRouteMatch);
            }
        }
        return true;
    }

    boolean shouldTheFilterProcessTheRequestAccordingToTheUriMatch(UriRouteMatch<?, ?> uriRouteMatch) {
        return shouldTheFilterProcessTheRequestAccordingToTheUriMatch(uriRouteMatch.getUri());
    }

    boolean shouldTheFilterProcessTheRequestAccordingToTheUriMatch(String uri) {
        boolean matches = PathMatcher.REGEX.matches(csrfFilterConfiguration.getRegexPattern(), uri);
        if (!matches) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Request uri {} does not match fitler regex pattern {}", uri, csrfFilterConfiguration.getRegexPattern());
            }
            return false;
        }
        return true;
    }

    private CompletableFuture<@Nullable HttpResponse<?>> reactiveFilter(HttpRequest<?> request) {
        List<CompletableFuture<Boolean>> futures = futureCsrfTokenResolvers.stream()
                .map(resolver -> resolveAndValidate(resolver, request))
                .toList();
        CompletableFuture<?>[] futuresArray = futures.toArray(new CompletableFuture<?>[0]);
        return  CompletableFuture.allOf(futuresArray)
                .thenApply(v -> futures.stream().map(CompletableFuture::join).toList())
                .thenApply(validations -> {
                    if (validations.stream().anyMatch(Boolean::booleanValue)) {
                        return null;
                    } else if (LOG.isTraceEnabled()) {
                        LOG.trace("CSRF Token validation failed");
                    }
                    return unauthorized(request);
                });
    }

    /**
     * Resolves the CSRF token with the supplied resolver and validates it. A resolver which fails, for example because
     * the request body cannot be parsed, counts as a failed validation so that the request is rejected instead of
     * answered with a server error. The failure message is not logged because it may contain the raw request body.
     * @param resolver CSRF token resolver
     * @param request HTTP request
     * @return Whether the token resolved by the resolver is valid
     */
    @NonNull
    private CompletableFuture<Boolean> resolveAndValidate(@NonNull FutureCsrfTokenResolver<HttpRequest<?>> resolver,
                                                          @NonNull HttpRequest<?> request) {
        CompletableFuture<String> tokenFuture;
        try {
            tokenFuture = resolver.resolveToken(request);
        } catch (RuntimeException e) {
            return CompletableFuture.completedFuture(resolverFailed(resolver.getClass(), e));
        }
        if (tokenFuture == null) {
            return CompletableFuture.completedFuture(resolverFailed(resolver.getClass(), new NullPointerException("resolver returned a null future")));
        }
        return tokenFuture.thenApply(csrfToken -> {
                    if (LOG.isTraceEnabled()) {
                        LOG.trace("CSRF Token resolved");
                    }
                    return csrfTokenValidator.validateCsrfToken(request, csrfToken);
                })
                .exceptionally(throwable -> resolverFailed(resolver.getClass(), throwable));
    }

    /**
     * A resolver failure counts as a failed validation. The exception is not logged, only its type, because its message
     * may contain the raw request body. A request body exceeding the maximum request size is not a validation failure:
     * the exception is propagated so that the client gets the matching status code. An {@link Error} is propagated as well.
     * @param resolverClass The class of the resolver or validator which failed
     * @param throwable The failure
     * @return {@code false}
     */
    private static boolean resolverFailed(@NonNull Class<?> resolverClass, @NonNull Throwable throwable) {
        Throwable cause = throwable instanceof CompletionException && throwable.getCause() != null ? throwable.getCause() : throwable;
        if (cause instanceof ContentLengthExceededException contentLengthExceededException) {
            throw contentLengthExceededException;
        }
        if (cause instanceof Error error) {
            throw error;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Request rejected by the CSRF Filter because {} failed with {}", resolverClass.getSimpleName(), cause.getClass().getName());
        }
        return false;
    }

    private CompletableFuture<@Nullable HttpResponse<?>> imperativeFilter(HttpRequest<?> request) {
        String csrfToken = resolveCsrfToken(request);
        if (StringUtils.isEmpty(csrfToken)) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Request rejected by the {} because no CSRF Token found", this.getClass().getSimpleName());
            }
            return reactiveUnauthorized(request);
        }
        boolean valid;
        try {
            valid = csrfTokenValidator.validateCsrfToken(request, csrfToken);
        } catch (RuntimeException e) {
            resolverFailed(csrfTokenValidator.getClass(), e);
            return reactiveUnauthorized(request);
        }
        if (valid) {
            return PROCEED;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Request rejected by the CSRF Filter because the CSRF Token validation failed");
        }
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

    /**
     * @param request HTTP request
     * @return The CSRF token, or {@code null} if no resolver found one or a resolver failed. A failing resolver rejects
     * the request like a missing token, except for a {@link ContentLengthExceededException}, which is propagated.
     */
    @Nullable
    private String resolveCsrfToken(@NonNull HttpRequest<?> request) {
        for (CsrfTokenResolver<HttpRequest<?>> tokenResolver : csrfTokenResolvers) {
            Optional<String> tokenOptional;
            try {
                tokenOptional = tokenResolver.resolveToken(request);
            } catch (RuntimeException e) {
                resolverFailed(tokenResolver.getClass(), e);
                return null;
            }
            if (tokenOptional.isPresent()) {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("CSRF token resolved via {}", tokenResolver.getClass().getSimpleName());
                }
                return tokenOptional.get();
            }
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("No CSRF token found in request");
        }
        return null;
    }

    @NonNull
    private CompletableFuture<@Nullable HttpResponse<?>> reactiveUnauthorized(@NonNull HttpRequest<?> request) {
        return CompletableFuture.completedFuture(unauthorized(request));
    }

    @NonNull
    private MutableHttpResponse<?> unauthorized(@NonNull HttpRequest<?> request) {
        Authentication authentication = ServerRequestContextSecurityContextSupplier.getSecurityContext(request).getAuthentication();
        return exceptionHandler.handle(request,
                new AuthorizationException(authentication));
    }

    @Override
    public int getOrder() {
        return ServerFilterPhase.SECURITY.order() + 100; // after {@link SecurityFilter}
    }
}
