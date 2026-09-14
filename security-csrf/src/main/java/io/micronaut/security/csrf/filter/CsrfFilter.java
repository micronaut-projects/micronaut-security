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
import io.micronaut.web.router.RouteAttributes;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
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
import io.micronaut.http.filter.FilterPatternStyle;
import io.micronaut.http.filter.ServerFilterPhase;
import io.micronaut.http.server.exceptions.ExceptionHandler;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthorizationException;
import io.micronaut.security.csrf.resolver.CsrfTokenResolver;
import io.micronaut.security.csrf.resolver.FutureCsrfTokenResolver;
import io.micronaut.security.csrf.validator.CsrfTokenValidator;
import io.micronaut.security.context.ServerRequestContextSecurityContextSupplier;
import io.micronaut.web.router.RouteMatch;
import io.micronaut.web.router.UriRouteMatch;
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
        // The RouteMatch is owned by the request and is still needed to execute the route, so it must not be closed here.
        RouteMatch<?> routeMatch = RouteAttributes.getRouteMatch(request).orElse(null);
        if (routeMatch instanceof UriRouteMatch<?, ?> uriRouteMatch) {
            return shouldTheFilterProcessTheRequestAccordingToTheUriMatch(uriRouteMatch);
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

    /**
     * Resolves CSRF tokens sequentially, in resolver order, and stops at the first token which validates.
     * Resolvers which may be expensive, such as those which parse the request body, are therefore not invoked if a cheaper resolver which runs before them, such as the HTTP header resolver, already produced a valid token.
     * @param request HTTP Request
     * @return A future which completes with {@code null} if a valid token was found; an unauthorized response otherwise.
     */
    @NonNull
    private CompletableFuture<@Nullable HttpResponse<?>> reactiveFilter(@NonNull HttpRequest<?> request) {
        return resolveAndValidate(request, 0, false);
    }

    @NonNull
    private CompletableFuture<@Nullable HttpResponse<?>> resolveAndValidate(@NonNull HttpRequest<?> request,
                                                                          int index,
                                                                          boolean tokenFound) {
        if (index >= futureCsrfTokenResolvers.size()) {
            return CompletableFuture.completedFuture(rejectRequest(request, tokenFound));
        }
        FutureCsrfTokenResolver<HttpRequest<?>> resolver = futureCsrfTokenResolvers.get(index);
        return resolveTokenOrNull(resolver, request).thenCompose(csrfToken -> {
            if (!hasText(csrfToken)) {
                return resolveAndValidate(request, index + 1, tokenFound);
            }
            if (LOG.isTraceEnabled()) {
                LOG.trace("CSRF Token resolved via {}", resolver.getClass().getSimpleName());
            }
            if (csrfTokenValidator.validateCsrfToken(request, csrfToken)) {
                return PROCEED;
            }
            return resolveAndValidate(request, index + 1, true);
        });
    }

    /**
     * Resolves a CSRF token with the supplied resolver. A resolver which throws or completes exceptionally is treated as if it had not found a token, so that the request is rejected by this filter instead of failing with a server error.
     * @param resolver CSRF Token resolver
     * @param request HTTP Request
     * @return A future which completes with the resolved token or {@code null} if the resolver did not find a token or failed.
     */
    @NonNull
    private CompletableFuture<@Nullable String> resolveTokenOrNull(@NonNull FutureCsrfTokenResolver<HttpRequest<?>> resolver,
                                                                   @NonNull HttpRequest<?> request) {
        CompletableFuture<String> future;
        try {
            future = resolver.resolveToken(request);
        } catch (RuntimeException e) {
            logResolverFailure(resolver, e);
            return CompletableFuture.completedFuture(null);
        }
        if (future == null) {
            return CompletableFuture.completedFuture(null);
        }
        return future.exceptionally(e -> {
            logResolverFailure(resolver, e);
            return null;
        });
    }

    private static void logResolverFailure(@NonNull FutureCsrfTokenResolver<HttpRequest<?>> resolver, @NonNull Throwable e) {
        if (LOG.isDebugEnabled()) {
            Throwable cause = e instanceof CompletionException && e.getCause() != null ? e.getCause() : e;
            LOG.debug("CSRF token resolver {} failed, treating it as no token resolved: {}", resolver.getClass().getName(), cause.getMessage());
        }
    }

    /**
     * Rejects the request once every resolver has been consulted without producing a valid token.
     * @param request HTTP Request
     * @param tokenFound Whether any resolver produced a non-blank token
     * @return an unauthorized response
     */
    @NonNull
    private HttpResponse<?> rejectRequest(@NonNull HttpRequest<?> request, boolean tokenFound) {
        if (!tokenFound) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Request rejected by the {} because no CSRF Token found", this.getClass().getSimpleName());
            }
        } else if (LOG.isDebugEnabled()) {
            LOG.debug("Request rejected by the CSRF Filter because the CSRF Token validation failed");
        }
        return unauthorized(request);
    }

    private static boolean hasText(@Nullable String csrfToken) {
        return csrfToken != null && !csrfToken.isBlank();
    }

    private CompletableFuture<@Nullable HttpResponse<?>> imperativeFilter(HttpRequest<?> request) {
        String csrfToken = resolveCsrfToken(request);
        if (!hasText(csrfToken)) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Request rejected by the {} because no CSRF Token found", this.getClass().getSimpleName());
            }
            return reactiveUnauthorized(request);
        }
        if (csrfTokenValidator.validateCsrfToken(request, csrfToken)) {
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

    @Nullable
    private String resolveCsrfToken(@NonNull HttpRequest<?> request) {
        for (CsrfTokenResolver<HttpRequest<?>> tokenResolver : csrfTokenResolvers) {
            Optional<String> tokenOptional = tokenResolver.resolveToken(request);
            if (tokenOptional.isPresent() && hasText(tokenOptional.get())) {
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
