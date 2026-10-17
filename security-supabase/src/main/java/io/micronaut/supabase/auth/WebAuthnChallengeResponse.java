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
import java.util.Map;

/**
 * Models the WebAuthnChallengeResponse object in Supabase Auth.
 *
 * @param id ID of the challenge.
 * @param type Type of the challenge.
 * @param expiresAt UNIX seconds of the timestamp past which the challenge should not be verified.
 * @param webauthn The value for {@code webauthn}.
 * @since 5.5.1
 */
@Serdeable
@Experimental
public record WebAuthnChallengeResponse(
    String id,
    String type,
    @JsonProperty("expires_at") @Nullable Integer expiresAt,
    Map<String, Object> webauthn
) {
}
