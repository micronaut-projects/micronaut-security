package io.micronaut.security.oauth2.url;

import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.runtime.server.EmbeddedServer;

import javax.annotation.Nonnull;
import javax.inject.Provider;
import javax.inject.Singleton;

@Singleton
public class DefaultHostResolver implements HostResolver {

    private final Provider<EmbeddedServer> embeddedServer;

    DefaultHostResolver(Provider<EmbeddedServer> embeddedServer) {
        this.embeddedServer = embeddedServer;
    }

    @Nonnull
    public String resolve(@Nonnull HttpRequest originating) {
        String host = originating.getHeaders().get(HttpHeaders.HOST);
        if (host == null) {
            host = embeddedServer.get().getURL().toString();
        } else {
            host = embeddedServer.get().getScheme() + "://" + host;
        }
        return host;
    }
}
