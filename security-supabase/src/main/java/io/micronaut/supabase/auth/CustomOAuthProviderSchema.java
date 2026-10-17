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
 * Represents a custom OAuth 2.0 or OIDC provider configuration
 *
 * @param id Unique provider identifier
 * @param providerType Type of OAuth provider
 * @param identifier Unique identifier for the provider (must start with 'custom:' prefix)
 * @param name Human-readable name of the provider
 * @param clientId OAuth client ID
 * @param acceptableClientIds Additional acceptable client IDs for token validation
 * @param scopes OAuth scopes to request (OIDC providers will automatically include 'openid')
 * @param pkceEnabled Whether PKCE (Proof Key for Code Exchange) is enabled
 * @param attributeMapping Maps provider claims to user attributes
 * @param customClaimsAllowlist Raw IdP claim keys copied verbatim into the user's custom_claims (e.g. groups, org_id). For OIDC
 *     providers these are read from the ID token claims (falling back to the userinfo response when no
 *     ID token is returned); for OAuth2 providers they are read from the userinfo response. Empty
 *     preserves no non-standard claims.
 * @param authorizationParams Additional parameters to include in authorization requests as string key-value pairs (cannot
 *     override reserved OAuth parameters)
 * @param enabled Whether the provider is enabled
 * @param emailOptional Whether email is optional for users from this provider
 * @param issuer OIDC issuer URL (required for OIDC providers)
 * @param discoveryUrl OIDC discovery URL (optional, defaults to {issuer}/.well-known/openid-configuration)
 * @param skipNonceCheck Skip nonce validation for OIDC (not recommended for production)
 * @param authorizationUrl OAuth 2.0 authorization endpoint (required for OAuth2 providers)
 * @param tokenUrl OAuth 2.0 token endpoint (required for OAuth2 providers)
 * @param userinfoUrl OAuth 2.0 userinfo endpoint (required for OAuth2 providers)
 * @param jwksUri JWKS URI for token validation (optional for OAuth2 providers)
 * @param createdAt The value for {@code createdAt}.
 * @param updatedAt The value for {@code updatedAt}.
 * @since 5.5.1
 */
@Serdeable
@Experimental
public record CustomOAuthProviderSchema(
    String id,
    @JsonProperty("provider_type") String providerType,
    String identifier,
    String name,
    @JsonProperty("client_id") String clientId,
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
