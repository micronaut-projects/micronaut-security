package io.micronaut.security.oauth2.url;

import io.micronaut.http.HttpRequest;

import javax.annotation.Nonnull;

public interface HostResolver {

    @Nonnull
    String resolve(@Nonnull HttpRequest originating);
}
