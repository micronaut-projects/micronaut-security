/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.session;

import io.micronaut.context.annotation.Replaces;
import io.micronaut.http.*;
import io.micronaut.security.authentication.AuthorizationException;
import io.micronaut.security.authentication.DefaultAuthorizationExceptionHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * An {@link io.micronaut.http.server.exceptions.ExceptionHandler} for {@link AuthorizationException} that
 * redirects to a configured URI.
 *
 * @author James Kleeh
 * @since 2.0.0
 */
@Singleton
@Replaces(DefaultAuthorizationExceptionHandler.class)
public class SessionAuthorizationExceptionHandler extends DefaultAuthorizationExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(SessionAuthorizationExceptionHandler.class);

    private final SecuritySessionConfiguration configuration;

    /**
     * @param configuration The session configuration
     */
    public SessionAuthorizationExceptionHandler(SecuritySessionConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public MutableHttpResponse<?> handle(HttpRequest request, AuthorizationException exception) {
        if (shouldHandleRequest(request)) {
            try {
                URI location = new URI(getRedirectUri(request, exception));
                //prevent redirect loop
                if (!request.getUri().equals(location)) {
                    return httpResponseWithUri(location);
                } else {
                    return super.handle(request, exception);
                }
            } catch (URISyntaxException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("Rejection redirect URL is invalid", e);
                }
                return HttpResponse.serverError();
            }
        } else {
            return super.handle(request, exception);
        }
    }

    /**
     * Decides whether the request should be handled with a redirect.
     *
     * @param request The HTTP Request
     * @return true if the request accepts text/html
     */
    protected boolean shouldHandleRequest(HttpRequest<?> request) {
        return configuration.isRedirectOnRejection() && request.getHeaders()
                .accept()
                .stream()
                .anyMatch(mediaType -> mediaType.equals(MediaType.TEXT_HTML_TYPE));
    }

    /**
     * @param request The request
     * @param exception The exception
     * @return The URI to redirect to
     */
    protected String getRedirectUri(HttpRequest<?> request, AuthorizationException exception) {
        String uri = exception.isForbidden() ? configuration.getForbiddenTargetUrl() :
                configuration.getUnauthorizedTargetUrl();
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
    protected MutableHttpResponse<?> httpResponseWithUri(URI location) {
        return HttpResponse.status(HttpStatus.SEE_OTHER)
                .headers((headers) ->
                        headers.location(location)
                );
    }
}
