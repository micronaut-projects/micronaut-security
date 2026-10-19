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
import jakarta.validation.constraints.NotNull;
import org.jspecify.annotations.Nullable;
import java.util.Map;

/**
 * Challenge issued by {@code POST /factors/{factorId}/challenge} for a {@code webauthn} factor.
 *
 * <p>The {@code webauthn} map carries the browser options: {@link CredentialCreationOptions} when the
 * factor is still unverified and must be registered, or {@link CredentialRequestOptions} when an
 * existing credential must authenticate. Return the browser's answer through the factor verification
 * request before the challenge expires.</p>
 *
 * @param id Challenge identifier to send with the verification request
 * @param type Factor type the challenge belongs to; always {@code webauthn}
 * @param expiresAt Unix epoch seconds after which the challenge can no longer be verified
 * @param webauthn WebAuthn creation or request options to pass to the browser
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record WebAuthnChallengeResponse(
    @NotBlank String id,
    @NotBlank String type,
    @JsonProperty("expires_at") @Nullable Integer expiresAt,
    @NotNull Map<String, Object> webauthn) {
}
