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
