package io.micronaut.security.oauth2.url;

import io.micronaut.http.HttpRequest;

/**
 * @author James Kleeh
 * @since 1.0.0
 */
public interface UrlBuilder {

    /**
     *
     * @param originating Originating HTTP Request
     * @param providerName OAuth 2 Provider
     * @return Url
     */
    String build(HttpRequest originating, String providerName);

    /**
     *
     * @param providerName OAuth 2 Provider
     * @return URL path
     */
    String getPath(String providerName);
}
