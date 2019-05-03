/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.oauth2.url;

import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.runtime.server.EmbeddedServer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.inject.Provider;
import javax.inject.Singleton;

/**
 * Default implementation of {@link HostResolver}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
public class DefaultHostResolver implements HostResolver {

    private final Provider<EmbeddedServer> embeddedServer;

    /**
     * @param embeddedServer The embedded server
     */
    public DefaultHostResolver(Provider<EmbeddedServer> embeddedServer) {
        this.embeddedServer = embeddedServer;
    }

    /**
     * Resolves the host in the following strategies in order:
     * 1. The HOST header of the request, if not null
     * 2. The host of the request URI, if not null
     * 3. The host of the embedded server URI
     *
     * @param current The current request
     * @return The host
     */
    @Nonnull
    public String resolve(@Nullable HttpRequest current) {
        String host = null;
        if (current != null) {
            host = current.getHeaders().get(HttpHeaders.HOST);
            if (host == null) {
                host = current.getUri().getHost();
            }
        }
        if (host == null) {
            host = embeddedServer.get().getURL().getHost();
        }
        return embeddedServer.get().getScheme() + "://" + host;
    }
}
