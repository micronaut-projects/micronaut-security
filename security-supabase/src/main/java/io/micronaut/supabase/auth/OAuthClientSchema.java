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
 * Represents an OAuth 2.1 client
 *
 * @param clientId Unique client identifier
 * @param clientName Human-readable name of the client application
 * @param clientSecret Client secret for confidential clients (only returned on registration/regeneration)
 * @param clientType Type of the client
 * @param tokenEndpointAuthMethod Authentication method for the token endpoint
 * @param registrationType Registration type of the client
 * @param clientUri URL of the client application's homepage
 * @param logoUri URL of the client application's logo
 * @param redirectUris Array of redirect URIs used by the client
 * @param grantTypes OAuth grant types the client is authorized to use
 * @param responseTypes OAuth response types the client can use
 * @param scope Space-separated list of scope values
 * @param createdAt The value for {@code createdAt}.
 * @param updatedAt The value for {@code updatedAt}.
 * @since 5.5.1
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
