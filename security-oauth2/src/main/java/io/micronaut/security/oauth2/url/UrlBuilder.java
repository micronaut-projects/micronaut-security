package io.micronaut.security.oauth2.url;

import io.micronaut.http.HttpRequest;

public interface UrlBuilder {

    String build(HttpRequest originating, String providerName);

    String getPath(String providerName);
}
