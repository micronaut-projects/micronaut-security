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
 * Client application registered with the Supabase Auth OAuth 2.1 authorization server.
 *
 * <p>Clients are created either by an administrator through {@code /admin/oauth/clients} or, when dynamic
 * registration is enabled, by the application itself through {@code POST /oauth/clients/register}. The
 * client secret is returned only when it is created or regenerated.</p>
 *
 * @param clientId Server-assigned client identifier, a UUID
 * @param clientName Human-readable name shown to users on the consent page
 * @param clientSecret Secret of a confidential client; present only in registration and regeneration responses
 * @param clientType Either {@code public} or {@code confidential}
 * @param tokenEndpointAuthMethod How the client authenticates at the token endpoint: {@code none},
 *                                {@code client_secret_basic} or {@code client_secret_post}
 * @param registrationType How the client was registered, either {@code dynamic} or {@code manual}
 * @param clientUri Homepage of the client application
 * @param logoUri Logo of the client application shown on the consent page
 * @param redirectUris Redirect URIs the client may use; {@code http} is permitted only for loopback hosts
 * @param grantTypes Grant types the client may use: {@code authorization_code} and {@code refresh_token}
 * @param responseTypes Response types the client may request; currently {@code code}
 * @param scope Space-separated scopes the client may request
 * @param createdAt Creation timestamp in RFC 3339 format
 * @param updatedAt Last modification timestamp in RFC 3339 format
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record OAuthClientSchema(
    @JsonProperty("client_id") @Nullable String clientId,
    @JsonProperty("client_name") @Nullable String clientName,
    @JsonProperty("client_secret") @Nullable String clientSecret,
    @JsonProperty("client_type") @Nullable String clientType,
    @JsonProperty("token_endpoint_auth_method") @Nullable String tokenEndpointAuthMethod,
    @JsonProperty("registration_type") @Nullable String registrationType,
    @JsonProperty("client_uri") @Nullable String clientUri,
    @JsonProperty("logo_uri") @Nullable String logoUri,
    @JsonProperty("redirect_uris") @Nullable List<String> redirectUris,
    @JsonProperty("grant_types") @Nullable List<String> grantTypes,
    @JsonProperty("response_types") @Nullable List<String> responseTypes,
    @Nullable String scope,
    @JsonProperty("created_at") @Nullable String createdAt,
    @JsonProperty("updated_at") @Nullable String updatedAt
) {
}
