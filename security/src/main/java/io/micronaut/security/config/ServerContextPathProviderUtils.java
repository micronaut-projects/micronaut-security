/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.config;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.context.ServerContextPathProvider;
import io.micronaut.http.uri.UriBuilder;

/**
 * Utility methods to prepend a URL with the context path provided via {@link ServerContextPathProvider}.
 * @author Sergio del Amo
 * @since 3.7.1
 */
@Internal
public final class ServerContextPathProviderUtils {
    private ServerContextPathProviderUtils() {
    }

    /**
     *
     * @param url The url to be prefixed by the context path
     * @param serverContextPathProvider context path provider
     * @return the url prepended with the context path. For url /bar and context path foo the method returns /foo/bar
     */
    @NonNull
    public static String prependContextPath(@NonNull String url,
                                            @NonNull ServerContextPathProvider serverContextPathProvider) {
        String contextPath = serverContextPathProvider.getContextPath();
        return contextPath == null ?
            url :
            UriBuilder.of("/")
                .path(contextPath)
                .build() + url;
    }
}
