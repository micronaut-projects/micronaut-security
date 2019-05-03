package io.micronaut.security.oauth2.url;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.http.uri.UriTemplate;

import java.util.HashMap;
import java.util.Map;

public abstract class AbstractUrlBuilder implements UrlBuilder {

    private final HostResolver hostResolver;
    private final String uriTemplate;

    AbstractUrlBuilder(HostResolver hostResolver, String uriTemplate) {
        this.hostResolver = hostResolver;
        this.uriTemplate = uriTemplate;
    }

    @Override
    public String build(HttpRequest originating, String providerName) {
        return UriBuilder.of(hostResolver.resolve(originating))
                .path(getPath(providerName))
                .build()
                .toString();
    }

    @Override
    public String getPath(String providerName) {
        Map<String, Object> uriParams = new HashMap<>(1);
        uriParams.put("provider", providerName);
        return UriTemplate.of(uriTemplate).expand(uriParams);
    }
}
