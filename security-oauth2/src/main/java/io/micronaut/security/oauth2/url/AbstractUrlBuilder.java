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

import io.micronaut.http.HttpRequest;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.http.uri.UriTemplate;

import java.util.HashMap;
import java.util.Map;

/**
 * Base {@link UrlBuilder} class to extend from that delegates
 * host resolution to a {@link HostResolver}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public abstract class AbstractUrlBuilder implements UrlBuilder {

    private final HostResolver hostResolver;
    private final String uriTemplate;

    /**
     * Builds an absolute URL with the provider host resolver and uri
     * template. The template may contain a {provider} variable segment
     * that will be replaced with the given OAuth 2.0 provider name.
     *
     * @param hostResolver The host resolver
     * @param uriTemplate The URI template
     */
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
