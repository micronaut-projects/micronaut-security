package io.micronaut.security.oauth2.bearer;

import io.micronaut.http.MutableHttpRequest;

/**
 * Complements http requests with authorization headers.
 *
 * @author svishnyakoff
 * @since 1.3.0
 */
public interface IntrospectionEndpointAuthStrategy {

    /**
     * Prepares request by adding required authorization headers before calling token introspection endpoint.
     *
     * @param request request to introspection endpoint that need be authorized
     * @param <T>     request body
     * @return new http request with authorization header.
     */
    <T> MutableHttpRequest<T> authorizeRequest(MutableHttpRequest<T> request);
}
