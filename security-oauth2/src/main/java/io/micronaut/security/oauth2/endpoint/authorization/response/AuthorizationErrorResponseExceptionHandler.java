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
package io.micronaut.security.oauth2.endpoint.authorization.response;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.server.exceptions.ExceptionHandler;
import io.micronaut.http.server.exceptions.response.ErrorContext;
import io.micronaut.http.server.exceptions.response.ErrorResponseProcessor;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RedirectService;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * An exception handler for {@link AuthorizationErrorResponseException}.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Requires(classes = ExceptionHandler.class)
@Requires(beans = ErrorResponseProcessor.class)
@Singleton
public class AuthorizationErrorResponseExceptionHandler implements ExceptionHandler<AuthorizationErrorResponseException, MutableHttpResponse<?>> {
    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationErrorResponseExceptionHandler.class);

    private final RedirectConfiguration redirectConfiguration;

    private final RedirectService redirectService;

    private final ErrorResponseProcessor<?> errorResponseProcessor;

    /**
     *
     * @param redirectConfiguration Redirect Configuration
     * @param redirectService Redirect Service
     * @param errorResponseProcessor Error Response Processor
     */
    public AuthorizationErrorResponseExceptionHandler(RedirectConfiguration redirectConfiguration,
                                                      RedirectService redirectService,
                                                      ErrorResponseProcessor<?> errorResponseProcessor) {
        this.redirectConfiguration = redirectConfiguration;
        this.redirectService = redirectService;
        this.errorResponseProcessor = errorResponseProcessor;
    }

    @Override
    public MutableHttpResponse<?> handle(HttpRequest request, AuthorizationErrorResponseException exception) {
        if (this.redirectConfiguration == null ||
            this.redirectService == null ||
            this.errorResponseProcessor == null) {
            return HttpResponse.badRequest(exception.getAuthorizationErrorResponse());
        }

        if (!shouldRedirect(request, exception)) {
            return httpResponseWithStatus(request, exception);
        }
        URI location;
        try {
            location = new URI(getRedirectUri(request, exception));
        } catch (URISyntaxException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("redirect URL is invalid", e);
            }
            return HttpResponse.serverError();
        }
        //prevent redirect loop
        return request.getUri().equals(location) ?
            httpResponseWithStatus(request, exception) :
            httpResponseWithStatus(location);

    }

    /**
     * Builds a HTTP Response redirection to the supplied location.
     *
     * @param location The Uri to redirect to
     * @return an HTTP response with the Uri as location
     */
    @NonNull
    protected MutableHttpResponse<?> httpResponseWithStatus(@NonNull URI location) {
        return HttpResponse.seeOther(location);
    }

    /**
     * @param request The request
     * @param exception The exception
     * @return The response to be used when a redirect is not appropriate
     */
    @NonNull
    protected MutableHttpResponse<?> httpResponseWithStatus(@NonNull HttpRequest<?> request,
                                                            @NonNull AuthorizationErrorResponseException exception) {
        return errorResponseProcessor.processResponse(ErrorContext.builder(request)
            .cause(exception)
            .build(), HttpResponse.badRequest(exception.getAuthorizationErrorResponse()));
    }

    /**
     * @param request The request
     * @param exception The exception
     * @return The URI to redirect to
     */
    @NonNull
    protected String getRedirectUri(@NonNull HttpRequest<?> request,
                                    @NonNull AuthorizationErrorResponseException exception) {
        String uri = redirectService.loginFailureUrl();
        if (LOG.isDebugEnabled()) {
            LOG.debug("redirect uri: {}", uri);
        }
        return uri;
    }

    /**
     * Decides whether the request should be handled with a redirect.
     *
     * @param request The HTTP Request
     * @param exception The authorization exception
     * @return true if the request accepts text/html
     */
    protected boolean shouldRedirect(@NonNull HttpRequest<?> request,
                                     @NonNull AuthorizationErrorResponseException exception) {
        return redirectConfiguration != null &&
            redirectConfiguration.isEnabled() &&
            acceptsHtml(request);
    }

    private static boolean acceptsHtml(@NonNull HttpRequest<?> request) {
        return request.getHeaders()
            .accept()
            .stream()
            .anyMatch(mediaType -> mediaType.equals(MediaType.TEXT_HTML_TYPE));
    }
}
