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
import org.jspecify.annotations.Nullable;
import java.util.List;
import java.util.Map;

/**
 * PublicKeyCredentialCreationOptions for WebAuthn registration
 *
 * @param rp The value for {@code rp}.
 * @param user The value for {@code user}.
 * @param challenge A challenge to be signed by the authenticator
 * @param pubKeyCredParams List of supported public key algorithms
 * @param timeout Time (in milliseconds) that the caller is willing to wait for the call to complete
 * @param excludeCredentials List of credentials to exclude (prevent re-registration)
 * @param authenticatorSelection The value for {@code authenticatorSelection}.
 * @param attestation Attestation conveyance preference
 * @param attestationFormats Preferred attestation statement formats
 * @param hints Hints for the browser about what types of authenticators to show
 * @param extensions WebAuthn extensions to enable
 * @since 5.5.1
 */
@Serdeable
@Experimental
public record CredentialCreationOptions(
    Rp rp,
    User user,
    String challenge,
    List<PubKeyCredParam> pubKeyCredParams,
    @Nullable Integer timeout,
    @Nullable List<PublicKeyCredentialDescriptor> excludeCredentials,
    @Nullable AuthenticatorSelection authenticatorSelection,
    @Nullable String attestation,
    @Nullable List<String> attestationFormats,
    @Nullable List<String> hints,
    @Nullable Map<String, Object> extensions
) {
    /**
     * Models the Rp object in Supabase Auth.
     *
     * @param id Relying Party ID (usually the domain)
     * @param name Human-readable Relying Party name
     * @since 5.5.1
     */
    @Serdeable
    @Experimental
    public record Rp(
        String id,
        String name
    ) {
    }
    /**
     * Models the User object in Supabase Auth.
     *
     * @param id User handle (opaque byte sequence, base64url encoded string or raw bytes)
     * @param name User account identifier (e.g., username or email)
     * @param displayName Human-readable user display name
     * @since 5.5.1
     */
    @Serdeable
    @Experimental
    public record User(
        String id,
        String name,
        String displayName
    ) {
    }
    /**
     * Models the PubKeyCredParam object in Supabase Auth.
     *
     * @param type The value for {@code type}.
     * @param alg COSE algorithm identifier (e.g., -7 for ES256, -257 for RS256)
     * @since 5.5.1
     */
    @Serdeable
    @Experimental
    public record PubKeyCredParam(
        String type,
        Integer alg
    ) {
    }
    /**
     * Models the AuthenticatorSelection object in Supabase Auth.
     *
     * @param authenticatorAttachment Preferred authenticator type
     * @param requireResidentKey Whether to require a resident key (deprecated, use residentKey)
     * @param residentKey Resident key requirement
     * @param userVerification User verification requirement
     * @since 5.5.1
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
