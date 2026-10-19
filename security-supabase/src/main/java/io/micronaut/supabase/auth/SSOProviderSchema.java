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
 * SAML 2.0 single sign-on provider registered through {@code /admin/sso/providers}.
 *
 * <p>Users whose email domain matches one of the provider's domains are routed to it by
 * {@code POST /sso}. Supabase Auth serializes the domains under the JSON name {@code domains}, which
 * differs from the {@code sso_domains} name in the published OpenAPI document.</p>
 *
 * @param id Server-assigned provider identifier, a UUID
 * @param ssoDomains Email domains served by this provider
 * @param saml SAML configuration parsed from the identity provider metadata
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record SSOProviderSchema(
    @Nullable String id,
    @JsonProperty("domains") @Nullable List<SsoDomain> ssoDomains,
    @Nullable Saml saml
) {
    /**
     * Email domain mapped to an SSO provider.
     *
     * @param domain Email domain, for example {@code example.com}
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record SsoDomain(
        @Nullable String domain
    ) {
    }

    /**
     * SAML 2.0 details of an SSO provider.
     *
     * @param entityId Entity identifier of the identity provider, taken from its metadata
     * @param metadataXml Identity provider metadata document; omitted from list responses
     * @param metadataUrl URL the metadata was fetched from, when it was registered by URL
     * @param attributeMapping Mapping from SAML assertion attributes to user metadata
     * @since 0.0.1
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
