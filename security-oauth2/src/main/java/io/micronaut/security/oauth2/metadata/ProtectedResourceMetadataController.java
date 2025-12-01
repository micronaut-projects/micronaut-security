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
package io.micronaut.security.oauth2.metadata;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;

@Internal
@Requires(classes = HttpRequest.class)
@Controller
class ProtectedResourceMetadataController {
    private final ProtectedResourceMetadataProvider<HttpRequest<?>> protectedResourceMetadataProvider;

    ProtectedResourceMetadataController(ProtectedResourceMetadataProvider<HttpRequest<?>> protectedResourceMetadataProvider) {
        this.protectedResourceMetadataProvider = protectedResourceMetadataProvider;
    }

    @Secured(SecurityRule.IS_ANONYMOUS)
    @Get(ProtectedResourceMetadataConfiguration.PATH)
    ProtectedResourceMetadata getProtectedResourceMetadata(HttpRequest<?> request) {
        return protectedResourceMetadataProvider.get(request);
    }

    @Secured(SecurityRule.IS_ANONYMOUS)
    @Get(ProtectedResourceMetadataConfiguration.PATH + "{path:.+}")
    ProtectedResourceMetadata getProtectedResourceMetadata(@NonNull @PathVariable String path, HttpRequest<?> request) {
        return protectedResourceMetadataProvider.get(path, request);
    }
}
