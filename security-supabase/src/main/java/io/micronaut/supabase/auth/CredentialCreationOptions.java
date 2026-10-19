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

import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.jspecify.annotations.Nullable;
import java.util.List;
import java.util.Map;

/**
 * WebAuthn {@code PublicKeyCredentialCreationOptions} issued when a user enrols a WebAuthn factor.
 *
 * <p>Pass these options to the browser's {@code navigator.credentials.create()} call and return the
 * resulting credential through the factor verification request.</p>
 *
 * @param rp Relying party the credential is created for
 * @param user Account the credential is bound to
 * @param challenge Random challenge the authenticator must sign, base64url encoded
 * @param pubKeyCredParams Public key algorithms the relying party accepts, in order of preference
 * @param timeout Milliseconds the caller is willing to wait for the ceremony to complete
 * @param excludeCredentials Credentials already registered for the user, to prevent duplicate registration
 * @param authenticatorSelection Constraints on the authenticator the browser may use
 * @param attestation Attestation conveyance preference, such as {@code none} or {@code direct}
 * @param attestationFormats Attestation statement formats the relying party prefers
 * @param hints Hints about which kinds of authenticator the browser should offer
 * @param extensions WebAuthn extensions to enable, keyed by extension identifier
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record CredentialCreationOptions(
    @NotNull Rp rp,
    @NotNull User user,
    @NotBlank String challenge,
    @NotEmpty List<PubKeyCredParam> pubKeyCredParams,
    @Nullable Integer timeout,
    @Nullable List<PublicKeyCredentialDescriptor> excludeCredentials,
    @Nullable AuthenticatorSelection authenticatorSelection,
    @Nullable String attestation,
    @Nullable List<String> attestationFormats,
    @Nullable List<String> hints,
    @Nullable Map<String, Object> extensions
) {
    /**
     * WebAuthn relying party, the service the credential is scoped to.
     *
     * @param id Relying party identifier, usually the effective domain of the site
     * @param name Human-readable relying party name shown by the authenticator
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record Rp(
        @NotBlank String id,
        @NotBlank String name) {
    }

    /**
     * WebAuthn user entity the credential is created for.
     *
     * @param id Opaque user handle, base64url encoded
     * @param name Account identifier such as a username or email address
     * @param displayName Human-readable name shown by the authenticator
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record User(
        @NotBlank String id,
        @NotBlank String name,
        @NotBlank String displayName) {
    }

    /**
     * Public key algorithm the relying party accepts for a new credential.
     *
     * @param type Credential type; currently always {@code public-key}
     * @param alg COSE algorithm identifier, for example {@code -7} for ES256 or {@code -257} for RS256
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record PubKeyCredParam(
        @NotBlank String type,
        @NotNull Integer alg) {
    }

    /**
     * Constraints on which authenticators may take part in the registration ceremony.
     *
     * @param authenticatorAttachment Preferred attachment, either {@code platform} or {@code cross-platform}
     * @param requireResidentKey Legacy flag for requiring a discoverable credential; prefer {@code residentKey}
     * @param residentKey Discoverable credential requirement: {@code discouraged}, {@code preferred} or {@code required}
     * @param userVerification User verification requirement: {@code discouraged}, {@code preferred} or {@code required}
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record AuthenticatorSelection(
        @Nullable String authenticatorAttachment,
        @Nullable Boolean requireResidentKey,
        @Nullable String residentKey,
        @Nullable String userVerification
    ) {
    }
}
