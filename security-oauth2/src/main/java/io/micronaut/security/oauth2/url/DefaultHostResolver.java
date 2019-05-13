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

import io.micronaut.context.annotation.Value;
import io.micronaut.http.HttpRequest;
import io.micronaut.runtime.server.EmbeddedServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    protected static final Logger LOG = LoggerFactory.getLogger(DefaultHostResolver.class);
    private final Provider<EmbeddedServer> embeddedServer;

    private String hostHeaderName;
    private String schemeHeaderName;

    /**
     * @param embeddedServer The embedded server
     * @param hostHeaderName HTTP Header name to resolve host
     * @param schemeHeaderName HTTP Header name to resolve scheme
     */
    public DefaultHostResolver(Provider<EmbeddedServer> embeddedServer,
                               @Value("${micronaut.server.host-resolver-header:Host}") String hostHeaderName,
                               @Value("${micronaut.server.scheme-resolver-header:X-Forwarded-Proto}") String schemeHeaderName) {
        this.embeddedServer = embeddedServer;
        this.hostHeaderName = hostHeaderName;
        this.schemeHeaderName = schemeHeaderName;
    }


    /**
     * Resolves the host in the following strategies in order:
     * 1. The HOST header of the request, if not null
     * 2. The host of the request URI, if not null
     * 3. The scheme header of the request, if not null
     * 4. The host of the embedded server URI
     *
     * @param current The current request
     * @return The host
     */
    @Override
    @Nonnull
    public String resolve(@Nullable HttpRequest current) {
        return scheme(current) + "://" + host(current);
    }

    /**
     * Resolves the host in the following strategies in order:
     * 1. The HOST header of the request, if not null
     * 2. The host of the request URI, if not null
     * @param current Current Request
     * @param headerName HTTP Header name
     * @return the resolved host
     */
    protected String hostByHeaderName(@Nullable HttpRequest current, String headerName) {
        String host = null;
        if (current != null) {
            host = current.getHeaders().get(headerName);
            if (host == null) {
                host = current.getUri().getHost();
            }
        }
        return host;
    }

    /**
     *
     * @param current Current Request
     * @param headerName HTTP Header name
     * @return the resolved scheme
     */
    protected String schemeByHeaderName(@Nullable HttpRequest current, String headerName) {
        String scheme = null;
        if (current != null) {
            scheme = current.getHeaders().get(headerName);
            if (scheme == null) {
                scheme = current.getUri().getScheme();
            }
        }
        return scheme;
    }

    /**
     *
     * @param current Current Request
     * @return the resolved host
     */
    protected String host(@Nullable HttpRequest current) {
        String host = hostByHeaderName(current, getHostHeaderName());
        if (host == null) {
            return embeddedServer.get().getURL().getHost();
        }
        return host;
    }

    /**
     *
     * @param current The current request
     * @return the resolved scheme
     */
    protected String scheme(@Nullable HttpRequest current) {
        String scheme = schemeByHeaderName(current, getSchemeHeaderName());
        if (scheme == null) {
            return "http";
        }
        return scheme;
    }

    /**
     *
     * @return The HTTP Header name used to resolve the HOST
     */
    public String getHostHeaderName() {
        return hostHeaderName;
    }

    /**
     *
     * @return The HTTP Header name used to resolve the scheme
     */
    public String getSchemeHeaderName() {
        return schemeHeaderName;
    }
}
