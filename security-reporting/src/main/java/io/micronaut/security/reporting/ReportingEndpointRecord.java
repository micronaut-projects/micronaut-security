/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.reporting;

import io.micronaut.core.annotation.Introspected;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.net.URI;

/**
 * Immutable {@link ReportingEndpoint} implementation.
 *
 * <p>This record is convenient for {@link ReportingEndpointProvider} implementations that create
 * endpoints dynamically.</p>
 *
 * @param name endpoint name referenced by reporting policies
 * @param url absolute or relative endpoint URI
 * @since 5.4.0
 */
@Introspected
record ReportingEndpointRecord(@NotBlank @Pattern(regexp = "[a-z*][a-z0-9_.*-]*") String name,
                                      @NotNull URI url) implements ReportingEndpoint {
    @Override
    public String getName() {
        return name;
    }

    @Override
    public URI getUrl() {
        return url;
    }
}
