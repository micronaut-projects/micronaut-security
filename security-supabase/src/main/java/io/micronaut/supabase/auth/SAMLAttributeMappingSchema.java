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
 * Mapping from SAML assertion attributes to Supabase Auth user metadata.
 *
 * <p>Each key becomes a field of the user's metadata and is populated from the named SAML attribute of
 * the identity provider's assertion. For example {@code email} mapped to {@code mail} copies the
 * {@code mail} attribute into the user's email.</p>
 *
 * @param keys Mappings keyed by the target user attribute name
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record SAMLAttributeMappingSchema(
    @Nullable Map<String, AttributeMapping> keys
) {
    /**
     * Source of a single mapped user attribute.
     *
     * <p>Specify either {@code name} for one SAML attribute or {@code names} to try several in order.</p>
     *
     * @param name SAML attribute name to read the value from
     * @param names SAML attribute names tried in order until one is present
     * @param defaultValue Value used when none of the SAML attributes is present
     * @since 0.0.1
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
