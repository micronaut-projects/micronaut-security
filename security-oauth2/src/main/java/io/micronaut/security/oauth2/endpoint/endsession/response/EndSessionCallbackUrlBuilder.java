package io.micronaut.security.oauth2.endpoint.endsession.response;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.security.oauth2.configuration.endpoints.EndSessionConfiguration;
import io.micronaut.security.oauth2.url.HostResolver;
import io.micronaut.security.oauth2.url.UrlBuilder;

import javax.annotation.Nullable;
import javax.inject.Singleton;

@Singleton
public class EndSessionCallbackUrlBuilder implements UrlBuilder {

    private final HostResolver hostResolver;
    private final EndSessionConfiguration endSessionConfiguration;

    EndSessionCallbackUrlBuilder(HostResolver hostResolver,
                                 EndSessionConfiguration endSessionConfiguration) {
        this.hostResolver = hostResolver;
        this.endSessionConfiguration = endSessionConfiguration;
    }

    @Override
    public String build(HttpRequest originating, @Nullable String providerName) {
        return UriBuilder.of(hostResolver.resolve(originating))
                .path(getPath(providerName))
                .build()
                .toString();
    }

    @Override
    public String getPath(@Nullable String providerName) {
        return endSessionConfiguration.getRedirectUri();
    }
}
