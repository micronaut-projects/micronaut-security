/*
 * Copyright 2017-2025 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.utils;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.client.HttpClientConfiguration;

/**
 * An {@link HttpClientConfiguration} which copies the settings of another configuration but never follows redirects.
 *
 * <p>The HTTP clients Micronaut Security uses to talk to an identity provider (token endpoint, OpenID provider metadata)
 * must not follow redirects. Otherwise a malicious or compromised provider could make the application
 * send those requests, together with the client credentials or the user token, to any address the application can
 * reach (SSRF) and the application would treat whatever JSON it finds there as the response of the provider.</p>
 *
 * @author Sergio del Amo
 * @since 3.11.3
 */
@Internal
public final class NoRedirectHttpClientConfiguration extends HttpClientConfiguration {

    private final HttpClientConfiguration delegate;

    /**
     * @param delegate The configuration to copy the settings from.
     */
    public NoRedirectHttpClientConfiguration(@NonNull HttpClientConfiguration delegate) {
        super(delegate);
        this.delegate = delegate;
        super.setFollowRedirects(false);
    }

    /**
     * @return Always {@code false}. Requests to the identity provider never follow redirects.
     */
    @Override
    public boolean isFollowRedirects() {
        return false;
    }

    /**
     * Ignored. Requests to the identity provider never follow redirects.
     *
     * @param followRedirects ignored
     */
    @Override
    public void setFollowRedirects(boolean followRedirects) {
        // never follow redirects
    }

    @Override
    public ConnectionPoolConfiguration getConnectionPoolConfiguration() {
        return delegate.getConnectionPoolConfiguration();
    }
}
