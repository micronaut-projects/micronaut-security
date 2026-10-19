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
import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.Nullable;
import java.util.List;
import java.util.Map;

/**
 * Custom OAuth 2.0 or OpenID Connect identity provider registered through {@code /admin/custom-providers}.
 *
 * <p>Custom providers extend the built-in external providers. Users sign in with them by passing the
 * provider's {@code identifier} to {@code GET /authorize}. The client secret is write-only and never
 * returned.</p>
 *
 * @param id Server-assigned provider identifier
 * @param providerType Protocol the provider speaks, either {@code oauth2} or {@code oidc}
 * @param identifier Stable identifier chosen at creation; it must start with {@code custom:}
 * @param name Human-readable provider name
 * @param clientId Client identifier registered with the provider
 * @param acceptableClientIds Additional client identifiers accepted when validating tokens
 * @param scopes Scopes requested during authorization; OIDC providers always include {@code openid}
 * @param pkceEnabled Whether authorization requests use Proof Key for Code Exchange
 * @param attributeMapping Mapping from provider claims to Supabase user attributes
 * @param customClaimsAllowlist Provider claims copied verbatim into the user's custom claims. OIDC providers
 *                              read them from the ID token, falling back to the userinfo response; OAuth 2.0
 *                              providers read them from the userinfo response
 * @param authorizationParams Extra parameters appended to authorization requests; reserved OAuth parameters
 *                            cannot be overridden
 * @param enabled Whether users may sign in with this provider
 * @param emailOptional Whether users without an email address may sign in with this provider
 * @param issuer OIDC issuer URL; required for OIDC providers
 * @param discoveryUrl OIDC discovery document URL; defaults to the issuer's {@code .well-known/openid-configuration}
 * @param skipNonceCheck Whether OIDC nonce validation is skipped; not recommended for production
 * @param authorizationUrl OAuth 2.0 authorization endpoint; required for OAuth 2.0 providers
 * @param tokenUrl OAuth 2.0 token endpoint; required for OAuth 2.0 providers
 * @param userinfoUrl OAuth 2.0 userinfo endpoint; required for OAuth 2.0 providers
 * @param jwksUri JSON Web Key Set URL used to validate provider tokens
 * @param createdAt Creation timestamp in RFC 3339 format
 * @param updatedAt Last modification timestamp in RFC 3339 format
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record CustomOAuthProviderSchema(
    @NotBlank String id,
    @JsonProperty("provider_type") @NotBlank String providerType,
    @NotBlank String identifier,
    @NotBlank String name,
    @JsonProperty("client_id") @NotBlank String clientId,
    @JsonProperty("acceptable_client_ids") @Nullable List<String> acceptableClientIds,
    @Nullable List<String> scopes,
    @JsonProperty("pkce_enabled") @Nullable Boolean pkceEnabled,
    @JsonProperty("attribute_mapping") @Nullable Map<String, Object> attributeMapping,
    @JsonProperty("custom_claims_allowlist") @Nullable List<String> customClaimsAllowlist,
    @JsonProperty("authorization_params") @Nullable Map<String, String> authorizationParams,
    @Nullable Boolean enabled,
    @JsonProperty("email_optional") @Nullable Boolean emailOptional,
    @Nullable String issuer,
    @JsonProperty("discovery_url") @Nullable String discoveryUrl,
    @JsonProperty("skip_nonce_check") @Nullable Boolean skipNonceCheck,
    @JsonProperty("authorization_url") @Nullable String authorizationUrl,
    @JsonProperty("token_url") @Nullable String tokenUrl,
    @JsonProperty("userinfo_url") @Nullable String userinfoUrl,
    @JsonProperty("jwks_uri") @Nullable String jwksUri,
    @JsonProperty("created_at") @Nullable String createdAt,
    @JsonProperty("updated_at") @Nullable String updatedAt
) {
}
