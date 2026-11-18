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
import io.micronaut.core.propagation.PropagatedContext;
import io.micronaut.web.router.RouteAttributes;
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
import io.micronaut.web.router.RouteMatch;
import io.micronaut.web.router.UriRouteMatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.List;
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
    private final CsrfTokenValidator<HttpRequest<?>> csrfTokenValidator;
    private final ExceptionHandler<AuthorizationException, MutableHttpResponse<?>> exceptionHandler;
    private final CsrfFilterConfiguration csrfFilterConfiguration;

    CsrfFilter(CsrfFilterConfiguration csrfFilterConfiguration,
               List<FutureCsrfTokenResolver<HttpRequest<?>>> futureCsrfTokenResolvers,
               List<CsrfTokenResolver<HttpRequest<?>>> csrfTokenResolvers,
               CsrfTokenValidator<HttpRequest<?>> csrfTokenValidator,
               ExceptionHandler<AuthorizationException, MutableHttpResponse<?>> exceptionHandler) {
        this.futureCsrfTokenResolvers = FutureCsrfTokenResolver.of(csrfTokenResolvers, futureCsrfTokenResolvers);
        this.csrfTokenValidator = csrfTokenValidator;
        this.exceptionHandler = exceptionHandler;
        this.csrfFilterConfiguration = csrfFilterConfiguration;
    }

    @RequestFilter
    public CompletableFuture<@Nullable HttpResponse<?>> csrfFilter(HttpRequest<?> request) {
        if (!shouldTheFilterProcessTheRequestAccordingToTheUriMatch(request)) {
            return PROCEED;
        }
        if (!shouldTheFilterProcessTheRequestAccordingToTheHttpMethod(request)) {
            return PROCEED;
        }
        if (!shouldTheFilterProcessTheRequestAccordingToTheContentType(request)) {
            return PROCEED;
        }
        return resolveAndValidate(request, 0, false);
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
     * A resolver which does not find a token, which fails, or whose token does not validate, does not reject the request by itself: the next resolver is consulted.
     * @param request HTTP Request
     * @param index Index of the resolver to consult
     * @param tokenFound Whether a previous resolver produced a non-blank token
     * @return A future which completes with {@code null} if a valid token was found; an unauthorized response otherwise.
     */
    private CompletableFuture<@Nullable HttpResponse<?>> resolveAndValidate(HttpRequest<?> request,
                                                                          int index,
                                                                          boolean tokenFound) {
        if (index >= futureCsrfTokenResolvers.size()) {
            return CompletableFuture.completedFuture(rejectRequest(request, tokenFound));
        }
        FutureCsrfTokenResolver<HttpRequest<?>> resolver = futureCsrfTokenResolvers.get(index);
        // A resolver may complete on a thread carrying a different request's context.
        PropagatedContext context = PropagatedContext.getOrEmpty();
        return resolveTokenOrNull(resolver, request).thenCompose(csrfToken -> context.propagate(() -> {
            if (csrfToken == null || csrfToken.isBlank()) {
                return resolveAndValidate(request, index + 1, tokenFound);
            }
            if (LOG.isTraceEnabled()) {
                LOG.trace("CSRF Token resolved via {}", resolver);
            }
            if (isValid(request, csrfToken)) {
                return PROCEED;
            }
            return resolveAndValidate(request, index + 1, true);
        }));
    }

    private boolean isValid(HttpRequest<?> request, String csrfToken) {
        try {
            return csrfTokenValidator.validateCsrfToken(request, csrfToken);
        } catch (RuntimeException e) {
            componentFailed(csrfTokenValidator.getClass(), e);
            return false;
        }
    }

    /**
     * Resolves a CSRF token with the supplied resolver. A resolver which fails, for example because the request body
     * cannot be parsed, is treated as if it had not found a token, so that the request is rejected instead of answered
     * with a server error. The failure message is not logged because it may contain the raw request body.
     * @param resolver CSRF token resolver
     * @param request HTTP request
     * @return A future which completes with the resolved token or {@code null} if the resolver did not find a token or failed.
     */
    private CompletableFuture<@Nullable String> resolveTokenOrNull(FutureCsrfTokenResolver<HttpRequest<?>> resolver,
                                                                   HttpRequest<?> request) {
        // a resolver may break its contract and return null
        @Nullable CompletableFuture<@Nullable String> tokenFuture;
        try {
            tokenFuture = resolver.resolveToken(request);
        } catch (RuntimeException e) {
            componentFailed(resolver.getClass(), e);
            return CompletableFuture.completedFuture(null);
        }
        if (tokenFuture == null) {
            componentFailed(resolver.getClass(), new NullPointerException("resolver returned a null future"));
            return CompletableFuture.completedFuture(null);
        }
        return tokenFuture.exceptionally(throwable -> {
            componentFailed(resolver.getClass(), throwable);
            return null;
        });
    }

    /**
     * Rejects the request once every resolver has been consulted without producing a valid token.
     * @param request HTTP Request
     * @param tokenFound Whether any resolver produced a non-blank token
     * @return an unauthorized response
     */
    private HttpResponse<?> rejectRequest(HttpRequest<?> request, boolean tokenFound) {
        if (!tokenFound) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Request rejected by the {} because no CSRF Token found", this.getClass().getSimpleName());
            }
        } else if (LOG.isDebugEnabled()) {
            LOG.debug("Request rejected by the CSRF Filter because the CSRF Token validation failed");
        }
        return unauthorized(request);
    }

    /**
     * A failing resolver or validator does not yield a valid token. The exception is not logged, only its type, because
     * its message may contain the raw request body. A request body exceeding the maximum request size is not a
     * validation failure: the exception is propagated so that the client gets the matching status code. An
     * {@link Error} is propagated as well.
     * @param componentClass The class of the resolver or validator which failed
     * @param throwable The failure
     */
    private static void componentFailed(Class<?> componentClass, Throwable throwable) {
        Throwable cause = throwable instanceof CompletionException && throwable.getCause() != null ? throwable.getCause() : throwable;
        if (cause instanceof ContentLengthExceededException contentLengthExceededException) {
            throw contentLengthExceededException;
        }
        if (cause instanceof Error error) {
            throw error;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("{} failed with {}; treating it as no valid CSRF token", componentClass.getSimpleName(), cause.getClass().getName());
        }
    }

    private boolean shouldTheFilterProcessTheRequestAccordingToTheContentType(HttpRequest<?> request) {
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

    private boolean shouldTheFilterProcessTheRequestAccordingToTheHttpMethod(HttpRequest<?> request) {
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

    private MutableHttpResponse<?> unauthorized(HttpRequest<?> request) {
        Authentication authentication = ServerRequestContextSecurityContextSupplier.getSecurityContext(request).getAuthentication();
        return exceptionHandler.handle(request,
                new AuthorizationException(authentication));
    }

    @Override
    public int getOrder() {
        return ServerFilterPhase.SECURITY.order() + 100; // after {@link SecurityFilter}
    }
}
