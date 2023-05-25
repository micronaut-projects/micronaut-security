/*
 * Copyright 2017-2023 original authors
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
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.server.exceptions.ExceptionHandler;
import io.micronaut.http.server.exceptions.response.ErrorContext;
import io.micronaut.http.server.exceptions.response.ErrorResponseProcessor;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RedirectService;
import io.micronaut.security.errors.PriorToLoginPersistence;
import jakarta.inject.Singleton;
import java.net.URI;
import java.net.URISyntaxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides the default behavior for responding to an {@link AuthorizationException}.
 *
 * @author James Kleeh
 * @since 1.4.0
 */
@Requires(classes = ExceptionHandler.class)
@Singleton
public class DefaultAuthorizationExceptionHandler implements ExceptionHandler<AuthorizationException, MutableHttpResponse<?>> {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultAuthorizationExceptionHandler.class);

    private final ErrorResponseProcessor<?> errorResponseProcessor;

    private final RedirectConfiguration redirectConfiguration;

    private final RedirectService redirectService;
    private final PriorToLoginPersistence priorToLoginPersistence;

    /**
     * @param errorResponseProcessor ErrorResponse processor API
     * @param redirectConfiguration Redirect configuration
     * @param redirectService Redirection Service
     * @param priorToLoginPersistence Persistence mechanism to redirect to prior login url
     */
    public DefaultAuthorizationExceptionHandler(ErrorResponseProcessor<?> errorResponseProcessor,
                                                RedirectConfiguration redirectConfiguration,
                                                RedirectService redirectService,
                                                @Nullable PriorToLoginPersistence priorToLoginPersistence) {
        this.errorResponseProcessor = errorResponseProcessor;
        this.redirectConfiguration = redirectConfiguration;
        this.redirectService = redirectService;
        this.priorToLoginPersistence = priorToLoginPersistence;
    }

    @Override
    public MutableHttpResponse<?> handle(HttpRequest request, AuthorizationException exception) {
        if (shouldRedirect(request, exception)) {
            try {
                URI location = new URI(getRedirectUri(request, exception));
                //prevent redirect loop
                if (!request.getUri().equals(location)) {
                    MutableHttpResponse<?> response = httpResponseWithStatus(location);
                    if (priorToLoginPersistence != null && !exception.isForbidden()) {
                        priorToLoginPersistence.onUnauthorized(request, response);
                    }
                    return response;
                }
                return httpResponseWithStatus(request, exception);
            } catch (URISyntaxException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("Rejection redirect URL is invalid", e);
                }
                return HttpResponse.serverError();
            }
        }
        return httpResponseWithStatus(request, exception);
    }

    /**
     * @param request The request
     * @param exception The exception
     * @return The response to be used when a redirect is not appropriate
     */
    protected MutableHttpResponse<?> httpResponseWithStatus(HttpRequest<?> request, AuthorizationException exception) {
        HttpStatus status = exception.isForbidden() ? HttpStatus.FORBIDDEN : HttpStatus.UNAUTHORIZED;
        return errorResponseProcessor.processResponse(ErrorContext.builder(request)
            .cause(exception)
            .errorMessage(status.getReason())
            .build(), HttpResponse.status(status));
    }

    /**
     * Decides whether the request should be handled with a redirect.
     *
     * @param request The HTTP Request
     * @param exception The authorization exception
     * @return true if the request accepts text/html
     */
    protected boolean shouldRedirect(HttpRequest<?> request, AuthorizationException exception) {
        if (redirectConfiguration != null && redirectConfiguration.isEnabled()) {
            return (
                    (exception.isForbidden() && redirectConfiguration.getForbidden().isEnabled()) ||
                            (!exception.isForbidden() && redirectConfiguration.getUnauthorized().isEnabled())
            ) && request.getHeaders()
                    .accept()
                    .stream()
                    .anyMatch(mediaType -> mediaType.equals(MediaType.TEXT_HTML_TYPE));
        } else {
            return false;
        }
    }

    /**
     * @param request The request
     * @param exception The exception
     * @return The URI to redirect to
     */
    protected String getRedirectUri(HttpRequest<?> request, AuthorizationException exception) {
        String uri = exception.isForbidden() ? redirectService.forbiddenUrl() :
                redirectService.unauthorizedUrl();
        if (LOG.isDebugEnabled()) {
            LOG.debug("redirect uri: {}", uri);
        }
        return uri;
    }

    /**
     * Builds a HTTP Response redirection to the supplied location.
     *
     * @param location The Uri to redirect to
     * @return an HTTP response with the Uri as location
     */
    protected MutableHttpResponse<?> httpResponseWithStatus(URI location) {
        return HttpResponse.status(HttpStatus.SEE_OTHER)
                .headers(headers -> headers.location(location));
    }
}
