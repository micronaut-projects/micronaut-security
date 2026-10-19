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
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.jspecify.annotations.Nullable;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Request bodies for {@link SupabaseAuthClient} operations whose schemas are declared inline in the
 * Supabase Auth OpenAPI document rather than as named components.
 *
 * <p>All records are JSON bodies except {@link OAuthTokenRequest}, which is sent form-encoded. Null fields
 * are optional and may be omitted from the request.</p>
 *
 * @since 0.0.1
 */
@Experimental
public final class SupabaseAuthRequests {

    private SupabaseAuthRequests() {
    }

    /**
     * Request fields for the grant-specific token endpoint.
     *
     * @param refreshToken Refresh token for the refresh-token grant
     * @param password User password for password authentication
     * @param email User email address
     * @param phone User phone number
     * @param idToken OpenID Connect identity token
     * @param accessToken Access token accompanying an identity token when required
     * @param nonce Expected identity-token nonce
     * @param provider Identity-token provider
     * @param clientId Identity-token client identifier
     * @param issuer Identity-token issuer
     * @param security CAPTCHA security fields
     * @param authCode Authorization code for the PKCE grant
     * @param codeVerifier PKCE code verifier
     * @param message Signed Web3 authentication message
     * @param signature Signature of the Web3 message
     * @param chain Blockchain used by the Web3 message
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record TokenRequest(
        @JsonProperty("refresh_token") @Nullable String refreshToken,
        @Nullable String password,
        @Nullable String email,
        @Nullable String phone,
        @JsonProperty("id_token") @Nullable String idToken,
        @JsonProperty("access_token") @Nullable String accessToken,
        @Nullable String nonce,
        @Nullable String provider,
        @JsonProperty("client_id") @Nullable String clientId,
        @Nullable String issuer,
        @JsonProperty("gotrue_meta_security") @Nullable GoTrueSecurity security,
        @JsonProperty("auth_code") @Nullable String authCode,
        @JsonProperty("code_verifier") @Nullable String codeVerifier,
        @Nullable String message,
        @Nullable String signature,
        @Nullable String chain
    ) {
    }

    /**
     * Request fields for verifying a one-time token.
     *
     * @param type Verification type
     * @param token Plain one-time token
     * @param tokenHash Hashed one-time token
     * @param email Email address associated with the token
     * @param phone Phone number associated with the token
     * @param redirectTo Redirect URI after successful verification
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record VerifyRequest(
        @Nullable String type,
        @Nullable String token,
        @JsonProperty("token_hash") @Nullable String tokenHash,
        @Nullable String email,
        @Nullable String phone,
        @JsonProperty("redirect_to") @Nullable String redirectTo
    ) {
    }

    /**
     * Request fields for a password recovery message.
     *
     * @param email Email address receiving the recovery message
     * @param codeChallenge PKCE code challenge
     * @param codeChallengeMethod PKCE challenge method
     * @param security CAPTCHA security fields
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record RecoverRequest(
        @NotBlank String email,
        @JsonProperty("code_challenge") @Nullable String codeChallenge,
        @JsonProperty("code_challenge_method") @Nullable String codeChallengeMethod,
        @JsonProperty("gotrue_meta_security") @Nullable GoTrueSecurity security
    ) {
    }

    /**
     * Request fields for resending a signup or account-change confirmation.
     *
     * @param email Email address associated with the confirmation
     * @param phone Phone number associated with the confirmation
     * @param type Resend operation type
     * @param security CAPTCHA security fields
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record ResendRequest(
        @Nullable String email,
        @Nullable String phone,
        @Nullable String type,
        @JsonProperty("gotrue_meta_security") @Nullable GoTrueSecurity security
    ) {
    }

    /**
     * Request fields for sending a magic link.
     *
     * @param email Destination email address
     * @param data User metadata to attach when creating a user
     * @param security CAPTCHA security fields
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record MagicLinkRequest(
        @NotBlank String email,
        @Nullable Map<String, Object> data,
        @JsonProperty("gotrue_meta_security") @Nullable GoTrueSecurity security
    ) {
    }

    /**
     * Request fields for sending a one-time password.
     *
     * @param email Destination email address
     * @param phone Destination phone number
     * @param channel Phone delivery channel
     * @param createUser Whether a user may be created when none exists
     * @param data User metadata to attach when creating a user
     * @param codeChallengeMethod PKCE challenge method
     * @param codeChallenge PKCE code challenge
     * @param security CAPTCHA security fields
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record OtpRequest(
        @Nullable String email,
        @Nullable String phone,
        @Nullable String channel,
        @JsonProperty("create_user") @Nullable Boolean createUser,
        @Nullable Map<String, Object> data,
        @JsonProperty("code_challenge_method") @Nullable String codeChallengeMethod,
        @JsonProperty("code_challenge") @Nullable String codeChallenge,
        @JsonProperty("gotrue_meta_security") @Nullable GoTrueSecurity security
    ) {
    }

    /**
     * Request fields for updating the authenticated user's account.
     *
     * @param email New email address
     * @param phone New phone number
     * @param password New password
     * @param nonce Nonce used to verify a changed email address
     * @param data User metadata
     * @param appMetadata Application metadata
     * @param channel Phone delivery channel
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record UpdateUserRequest(
        @Nullable String email,
        @Nullable String phone,
        @Nullable String password,
        @Nullable String nonce,
        @Nullable Map<String, Object> data,
        @JsonProperty("app_metadata") @Nullable Map<String, Object> appMetadata,
        @Nullable String channel
    ) {
    }

    /**
     * Request fields for enrolling a multi-factor authentication factor.
     *
     * @param factorType Factor type, such as {@code totp}, {@code phone}, or {@code webauthn}
     * @param friendlyName User-visible factor name
     * @param issuer Issuer name for a TOTP factor
     * @param phone Phone number for a phone factor
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record EnrollFactorRequest(
        @JsonProperty("factor_type") @NotBlank String factorType,
        @JsonProperty("friendly_name") @Nullable String friendlyName,
        @Nullable String issuer,
        @Nullable String phone
    ) {
    }

    /**
     * Request fields for creating a multi-factor authentication challenge.
     *
     * @param channel Phone delivery channel
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record ChallengeFactorRequest(
        @Nullable String channel
    ) {
    }

    /**
     * Request fields for verifying a multi-factor authentication challenge.
     *
     * @param challengeId Challenge identifier
     * @param code TOTP or SMS verification code
     * @param webauthn WebAuthn verification request
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record VerifyFactorRequest(
        @JsonProperty("challenge_id") @NotBlank String challengeId,
        @Nullable String code,
        @Nullable WebAuthn webauthn
    ) {
        /**
         * WebAuthn verification payload accepted by a factor challenge.
         *
         * @param type WebAuthn operation type, either {@code create} or {@code request}
         * @param credentialResponse Credential response returned by the WebAuthn client
         * @since 0.0.1
         */
        @Serdeable
        @Experimental
        public record WebAuthn(
            @NotBlank String type,
            @JsonProperty("credential_response") @NotNull Map<String, Object> credentialResponse) {
        }
    }

    /**
     * Optional request fields for generating multi-factor recovery codes.
     *
     * @param friendlyName Name displayed for the recovery-code factor
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record GenerateRecoveryCodesRequest(
        @JsonProperty("friendly_name") @Nullable String friendlyName
    ) {
    }

    /**
     * Request fields for redeeming a multi-factor recovery code.
     *
     * @param code Recovery code to redeem
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record VerifyRecoveryCodeRequest(
        @NotBlank String code) {
    }

    /**
     * Request fields for initiating single sign-on.
     *
     * @param domain Email domain used to find the SSO provider
     * @param providerId SSO provider identifier
     * @param redirectTo Redirect URI after SSO
     * @param skipHttpRedirect Whether to return the response without an HTTP redirect
     * @param codeChallenge PKCE code challenge
     * @param codeChallengeMethod PKCE challenge method
     * @param security CAPTCHA security fields
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record SsoRequest(
        @Nullable String domain,
        @JsonProperty("provider_id") @Nullable String providerId,
        @JsonProperty("redirect_to") @Nullable String redirectTo,
        @JsonProperty("skip_http_redirect") @Nullable Boolean skipHttpRedirect,
        @JsonProperty("code_challenge") @Nullable String codeChallenge,
        @JsonProperty("code_challenge_method") @Nullable String codeChallengeMethod,
        @JsonProperty("gotrue_meta_security") @Nullable GoTrueSecurity security
    ) {
    }

    /**
     * Request fields for inviting a user.
     *
     * @param email Email address to invite
     * @param data User metadata to attach to the invited account
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record InviteUserRequest(
        @NotBlank String email,
        @Nullable Map<String, Object> data
    ) {
    }

    /**
     * Request fields for generating an administrative email link.
     *
     * @param type Link type
     * @param email Email address associated with the link
     * @param newEmail New email address for email-change links
     * @param password Password to set for signup links
     * @param data User metadata
     * @param redirectTo Redirect URI after link verification
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record GenerateAdminLinkRequest(
        @NotBlank String type,
        @NotBlank String email,
        @JsonProperty("new_email") @Nullable String newEmail,
        @Nullable String password,
        @Nullable Map<String, Object> data,
        @JsonProperty("redirect_to") @Nullable String redirectTo
    ) {
    }

    /**
     * Request fields for updating an administrative user's multi-factor factor.
     *
     * <p>The current OpenAPI schema defines this body as an empty object.</p>
     *
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record UpdateAdminUserFactorRequest() {
    }

    /**
     * Request fields for registering an SSO provider.
     *
     * @param type SSO provider type, currently {@code saml}
     * @param metadataUrl Provider metadata URL
     * @param metadataXml Provider metadata document
     * @param domains Email domains served by the provider
     * @param attributeMapping SAML attribute mapping
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record CreateSsoProviderRequest(
        @NotBlank String type,
        @JsonProperty("metadata_url") @Nullable String metadataUrl,
        @JsonProperty("metadata_xml") @Nullable String metadataXml,
        @Nullable List<String> domains,
        @JsonProperty("attribute_mapping") @Nullable SAMLAttributeMappingSchema attributeMapping
    ) {
    }

    /**
     * Request fields for updating an SSO provider.
     *
     * @param metadataUrl Provider metadata URL
     * @param metadataXml Provider metadata document
     * @param domains Email domains served by the provider
     * @param attributeMapping SAML attribute mapping
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record UpdateSsoProviderRequest(
        @JsonProperty("metadata_url") @Nullable String metadataUrl,
        @JsonProperty("metadata_xml") @Nullable String metadataXml,
        @Nullable List<String> domains,
        @JsonProperty("attribute_mapping") @Nullable SAMLAttributeMappingSchema attributeMapping
    ) {
    }

    /**
     * Request fields for registering an OAuth client.
     *
     * @param clientName Human-readable client name
     * @param clientUri Client application homepage
     * @param logoUri Client application logo
     * @param redirectUris Allowed redirect URIs
     * @param clientType OAuth client type
     * @param tokenEndpointAuthMethod Client authentication method
     * @param grantTypes Allowed OAuth grant types
     * @param responseTypes Allowed OAuth response types
     * @param scope Space-separated scope values
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record OAuthClientRegistrationRequest(
        @JsonProperty("client_name") @NotBlank String clientName,
        @JsonProperty("client_uri") @Nullable String clientUri,
        @JsonProperty("logo_uri") @Nullable String logoUri,
        @JsonProperty("redirect_uris") @NotEmpty List<String> redirectUris,
        @JsonProperty("client_type") @Nullable String clientType,
        @JsonProperty("token_endpoint_auth_method") @Nullable String tokenEndpointAuthMethod,
        @JsonProperty("grant_types") @Nullable List<String> grantTypes,
        @JsonProperty("response_types") @Nullable List<String> responseTypes,
        @Nullable String scope
    ) {
    }

    /**
     * Request fields for updating an OAuth client.
     *
     * @param clientName Human-readable client name
     * @param clientUri Client application homepage
     * @param logoUri Client application logo
     * @param redirectUris Allowed redirect URIs
     * @param grantTypes Allowed OAuth grant types
     * @param tokenEndpointAuthMethod Client authentication method
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record OAuthClientUpdateRequest(
        @JsonProperty("client_name") @Nullable String clientName,
        @JsonProperty("client_uri") @Nullable String clientUri,
        @JsonProperty("logo_uri") @Nullable String logoUri,
        @JsonProperty("redirect_uris") @Nullable List<String> redirectUris,
        @JsonProperty("grant_types") @Nullable List<String> grantTypes,
        @JsonProperty("token_endpoint_auth_method") @Nullable String tokenEndpointAuthMethod
    ) {
    }

    /**
     * Form fields for exchanging an OAuth authorization code or refresh token.
     *
     * @param grantType OAuth grant type, either {@code authorization_code} or {@code refresh_token}
     * @param code Authorization code for the authorization-code grant
     * @param redirectUri Redirect URI used in the authorization request
     * @param codeVerifier PKCE code verifier for the authorization-code grant
     * @param refreshToken Refresh token for the refresh-token grant
     * @param clientId OAuth client identifier
     * @param clientSecret OAuth client secret
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record OAuthTokenRequest(
        @JsonProperty("grant_type") @NotBlank String grantType,
        @Nullable String code,
        @JsonProperty("redirect_uri") @Nullable String redirectUri,
        @JsonProperty("code_verifier") @Nullable String codeVerifier,
        @JsonProperty("refresh_token") @Nullable String refreshToken,
        @JsonProperty("client_id") @Nullable String clientId,
        @JsonProperty("client_secret") @Nullable String clientSecret
    ) {
        /**
         * Converts this request to the form fields expected by the OAuth token endpoint.
         * Null optional fields are omitted. The HTTP client encodes these values as form data.
         *
         * @return Form field names and values
         * @since 0.0.1
         */
        public Map<String, String> toMap() {
            Map<String, String> fields = new HashMap<>();
            fields.put("grant_type", grantType);
            if (code != null) {
                fields.put("code", code);
            }
            if (redirectUri != null) {
                fields.put("redirect_uri", redirectUri);
            }
            if (codeVerifier != null) {
                fields.put("code_verifier", codeVerifier);
            }
            if (refreshToken != null) {
                fields.put("refresh_token", refreshToken);
            }
            if (clientId != null) {
                fields.put("client_id", clientId);
            }
            if (clientSecret != null) {
                fields.put("client_secret", clientSecret);
            }
            return Map.copyOf(fields);
        }
    }

    /**
     * Request fields for creating a custom OAuth or OIDC provider.
     *
     * @param providerType Provider protocol type
     * @param identifier Provider identifier
     * @param name Human-readable provider name
     * @param clientId Provider client identifier
     * @param clientSecret Provider client secret
     * @param acceptableClientIds Additional accepted client identifiers
     * @param scopes OAuth scopes to request
     * @param pkceEnabled Whether to enable PKCE
     * @param attributeMapping Mapping from provider claims to user attributes
     * @param customClaimsAllowlist Provider claims copied to custom claims
     * @param authorizationParams Additional authorization request parameters
     * @param enabled Whether the provider is enabled
     * @param emailOptional Whether provider users may omit an email address
     * @param issuer OIDC issuer URL
     * @param discoveryUrl OIDC discovery URL
     * @param skipNonceCheck Whether to skip OIDC nonce validation
     * @param authorizationUrl OAuth authorization endpoint
     * @param tokenUrl OAuth token endpoint
     * @param userinfoUrl OAuth user-info endpoint
     * @param jwksUri JSON Web Key Set URL
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record CreateCustomOAuthProviderRequest(
        @JsonProperty("provider_type") @NotBlank String providerType,
        @NotBlank String identifier,
        @NotBlank String name,
        @JsonProperty("client_id") @NotBlank String clientId,
        @JsonProperty("client_secret") @NotBlank String clientSecret,
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
        @JsonProperty("jwks_uri") @Nullable String jwksUri
    ) {
    }

    /**
     * Request fields for updating a custom OAuth or OIDC provider.
     *
     * @param name Human-readable provider name
     * @param clientId Provider client identifier
     * @param clientSecret Provider client secret
     * @param acceptableClientIds Additional accepted client identifiers
     * @param scopes OAuth scopes to request
     * @param pkceEnabled Whether to enable PKCE
     * @param attributeMapping Mapping from provider claims to user attributes
     * @param customClaimsAllowlist Provider claims copied to custom claims
     * @param authorizationParams Additional authorization request parameters
     * @param enabled Whether the provider is enabled
     * @param emailOptional Whether provider users may omit an email address
     * @param issuer OIDC issuer URL
     * @param discoveryUrl OIDC discovery URL
     * @param skipNonceCheck Whether to skip OIDC nonce validation
     * @param authorizationUrl OAuth authorization endpoint
     * @param tokenUrl OAuth token endpoint
     * @param userinfoUrl OAuth user-info endpoint
     * @param jwksUri JSON Web Key Set URL
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record UpdateCustomOAuthProviderRequest(
        @Nullable String name,
        @JsonProperty("client_id") @Nullable String clientId,
        @JsonProperty("client_secret") @Nullable String clientSecret,
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
        @JsonProperty("jwks_uri") @Nullable String jwksUri
    ) {
    }

    /**
     * Request fields for approving or denying an OAuth authorization.
     *
     * @param action Consent action, either {@code approve} or {@code deny}
     * @since 0.0.1
     */
    @Serdeable
    @Experimental
    public record ConsentOAuthAuthorizationRequest(
        @NotBlank String action) {
    }
}
