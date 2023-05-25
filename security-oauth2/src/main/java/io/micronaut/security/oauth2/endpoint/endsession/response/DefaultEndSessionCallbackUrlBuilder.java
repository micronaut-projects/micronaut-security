/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.oauth2.endpoint.endsession.response;

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.oauth2.configuration.endpoints.EndSessionConfiguration;
import io.micronaut.security.oauth2.url.AbsoluteUrlBuilder;
import jakarta.inject.Singleton;
import java.net.URL;

/**
 * The default implementation of {@link EndSessionCallbackUrlBuilder}.
 *
 * @author James Kleeh
 * @since 1.2.0
 * @param <T> Request
 */
@Requires(beans = { AbsoluteUrlBuilder.class, EndSessionConfiguration.class })
@Singleton
public class DefaultEndSessionCallbackUrlBuilder<T> implements EndSessionCallbackUrlBuilder<T> {

    private final AbsoluteUrlBuilder<T> absoluteUrlBuilder;
    private final EndSessionConfiguration endSessionConfiguration;

    /**
     * @param absoluteUrlBuilder The URL builder
     * @param endSessionConfiguration The end session configuration
     */
    public DefaultEndSessionCallbackUrlBuilder(AbsoluteUrlBuilder<T> absoluteUrlBuilder,
                                               EndSessionConfiguration endSessionConfiguration) {
        this.absoluteUrlBuilder = absoluteUrlBuilder;
        this.endSessionConfiguration = endSessionConfiguration;
    }

    @Override
    public URL build(T originating) {
        return absoluteUrlBuilder.buildUrl(originating, endSessionConfiguration.getRedirectUri());
    }
}
