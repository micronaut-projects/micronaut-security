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
package io.micronaut.supabase.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import org.jspecify.annotations.Nullable;
import java.util.List;
import java.util.Map;

/**
 * Models the SAMLAttributeMappingSchema object in Supabase Auth.
 *
 * @param keys The value for {@code keys}.
 * @since 5.5.1
 */
@Serdeable
@Experimental
public record SAMLAttributeMappingSchema(
    @Nullable Map<String, AttributeMapping> keys
) {
    /**
     * Models the AttributeMapping object in Supabase Auth.
     *
     * @param name The value for {@code name}.
     * @param names The value for {@code names}.
     * @param defaultValue The value for {@code defaultValue}.
     * @since 5.5.1
     */
    @Serdeable
    @Experimental
    public record AttributeMapping(
        @Nullable String name,
        @Nullable List<String> names,
        @JsonProperty("default") @Nullable Object defaultValue
    ) {
    }
}
