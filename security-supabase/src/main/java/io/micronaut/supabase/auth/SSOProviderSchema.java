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

/**
 * Models the SSOProviderSchema object in Supabase Auth.
 *
 * @param id The value for {@code id}.
 * @param ssoDomains The value for {@code ssoDomains}.
 * @param saml The value for {@code saml}.
 * @since 5.5.1
 */
@Serdeable
@Experimental
public record SSOProviderSchema(
    @Nullable String id,
    @JsonProperty("sso_domains") @Nullable List<SsoDomain> ssoDomains,
    @Nullable Saml saml
) {
    /**
     * Models the SsoDomain object in Supabase Auth.
     *
     * @param domain The value for {@code domain}.
     * @since 5.5.1
     */
    @Serdeable
    @Experimental
    public record SsoDomain(
        @Nullable String domain
    ) {
    }
    /**
     * Models the Saml object in Supabase Auth.
     *
     * @param entityId The value for {@code entityId}.
     * @param metadataXml The value for {@code metadataXml}.
     * @param metadataUrl The value for {@code metadataUrl}.
     * @param attributeMapping The value for {@code attributeMapping}.
     * @since 5.5.1
     */
    @Serdeable
    @Experimental
    public record Saml(
        @JsonProperty("entity_id") @Nullable String entityId,
        @JsonProperty("metadata_xml") @Nullable String metadataXml,
        @JsonProperty("metadata_url") @Nullable String metadataUrl,
        @JsonProperty("attribute_mapping") @Nullable SAMLAttributeMappingSchema attributeMapping
    ) {
    }
}
