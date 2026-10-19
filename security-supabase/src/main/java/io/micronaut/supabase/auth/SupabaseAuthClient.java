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
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Delete;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.annotation.Put;
import io.micronaut.http.annotation.QueryValue;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.supabase.SupabaseApiKeyClientFilter;
import io.micronaut.supabase.SupabaseConfiguration;
import io.micronaut.supabase.auth.SupabaseAuthRequests.ChallengeFactorRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.ConsentOAuthAuthorizationRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.CreateCustomOAuthProviderRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.CreateSsoProviderRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.EnrollFactorRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.GenerateAdminLinkRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.GenerateRecoveryCodesRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.InviteUserRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.MagicLinkRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.OAuthClientRegistrationRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.OAuthClientUpdateRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.OAuthTokenRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.OtpRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.RecoverRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.ResendRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.SsoRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.TokenRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.UpdateAdminUserFactorRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.UpdateCustomOAuthProviderRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.UpdateSsoProviderRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.UpdateUserRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.VerifyFactorRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.VerifyRecoveryCodeRequest;
import io.micronaut.supabase.auth.SupabaseAuthRequests.VerifyRequest;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;

/**
 * Declarative client for the Supabase Auth (GoTrue) REST API.
 *
 * <p>For a hosted project set {@code supabase.project-id}, or {@code supabase.url} for a custom domain, and
 * {@link io.micronaut.supabase.SupabaseDiscoveryClient} resolves the client to the project URL. Requests are
 * sent below the Auth API path, {@code supabase.auth-path}, which defaults to {@code /auth/v1}. For a GoTrue
 * server that is not behind the Supabase gateway set {@code micronaut.http.services.supabase.url} to its URL,
 * which takes precedence over the project URL, and {@code supabase.auth-path} to an empty string if it serves
 * the API at its root. Several routes answer with redirects to the configured site URL, so set
 * {@code micronaut.http.services.supabase.follow-redirects} to {@code false} to inspect them.</p>
 *
 * <p>Credentials are split between configuration and method parameters:</p>
 * <ul>
 *   <li>The project API key is configured once through {@link io.micronaut.supabase.SupabaseConfiguration}
 *       and added to every request by {@link io.micronaut.supabase.SupabaseApiKeyClientFilter}: the
 *       publishable key on user-facing routes, the secret key on {@code /admin/**} and {@code /invite}.
 *       Neither is needed for a self-hosted GoTrue server reached directly, except that its administrative
 *       routes still need a legacy service-role JWT as the secret key.</li>
 *   <li>{@code authorization} parameters take the signed-in user's access token as a full
 *       {@code Authorization} header value including the {@code Bearer} scheme, typically obtained from
 *       {@link #token} or {@link #signup}.</li>
 * </ul>
 *
 * <p>Rejected requests surface as {@link io.micronaut.http.client.exceptions.HttpClientResponseException}
 * whose body deserializes to {@link ErrorSchema}, except {@code 404} responses, which methods returning
 * {@link HttpResponse} return as-is. Where the running server differs from the published OpenAPI
 * document, the client follows the server and notes the difference on the method.</p>
 *
 * @see <a href="https://github.com/supabase/auth/blob/master/openapi.yaml">Supabase Auth REST API</a>
 * @since 0.0.1
 */
@Experimental
@Client(id = SupabaseApiKeyClientFilter.SERVICE_ID, path = "${" + SupabaseConfiguration.AUTH_PATH_PROPERTY + ":" + SupabaseConfiguration.AUTH_PATH + "}")
public interface SupabaseAuthClient {

    /**
     * Issues access and refresh tokens for the requested grant type.
     *
     * @param grantType Grant type such as {@code password} or {@code refresh_token}
     * @param request Grant-specific request fields
     * @return The token response
     * @since 0.0.1
     */
    @Post("/token")
    HttpResponse<AccessTokenResponseSchema> token(@QueryValue("grant_type") String grantType,
                                                   @Body TokenRequest request);

    /**
     * Logs out the current user.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param scope Logout scope such as {@code local}, {@code global}, or {@code others}
     * @return The upstream response
     * @since 0.0.1
     */
    @Post("/logout")
    HttpResponse<?> logout(@Header("Authorization") String authorization,
                           @QueryValue("scope") @Nullable String scope);

    /**
     * Verifies a one-time token and redirects to the configured destination.
     *
     * @param token One-time verification token
     * @param type Verification type
     * @param redirectTo Optional destination after verification
     * @return The upstream redirect response
     * @since 0.0.1
     */
    @Get("/verify")
    HttpResponse<?> verifyLink(@QueryValue("token") String token,
                               @QueryValue("type") String type,
                               @QueryValue("redirect_to") @Nullable String redirectTo);

    /**
     * Verifies a one-time token supplied in the request body.
     *
     * @param request Verification fields
     * @return The token response
     * @since 0.0.1
     */
    @Post("/verify")
    HttpResponse<AccessTokenResponseSchema> verify(@Body VerifyRequest request);

    /**
     * Redirects the user to an external OAuth provider.
     *
     * @param provider OAuth provider name
     * @param scopes Space-separated OAuth scopes
     * @param inviteToken Optional invitation token
     * @param redirectTo Optional return URL
     * @param codeChallengeMethod Optional PKCE method
     * @return The upstream redirect response
     * @since 0.0.1
     */
    @Get("/authorize")
    HttpResponse<?> authorizeProvider(@QueryValue("provider") String provider,
                                      @QueryValue("scopes") String scopes,
                                      @QueryValue("invite_token") @Nullable String inviteToken,
                                      @QueryValue("redirect_to") @Nullable String redirectTo,
                                      @QueryValue("code_challenge_method") @Nullable String codeChallengeMethod);

    /**
     * Creates a user with the supplied signup payload.
     *
     * <p>GoTrue returns either a session response or a user object, depending
     * on whether email confirmation is required.</p>
     *
     * @param redirectTo Optional URL for the confirmation redirect
     * @param signupRequest Signup request fields, such as {@code email} and {@code password}
     * @return The upstream HTTP response
     * @since 0.0.1
     */
    @Post("/signup")
    HttpResponse<Map<String, Object>> signup(@QueryValue("redirect_to") @Nullable String redirectTo,
                                              @Body SignupRequest signupRequest);

    /**
     * Sends a password recovery message.
     *
     * @param request Recovery request fields
     * @return The upstream response body
     * @since 0.0.1
     */
    @Post("/recover")
    HttpResponse<Map<String, Object>> recover(@Body RecoverRequest request);

    /**
     * Resends a signup or account change confirmation message.
     *
     * @param request Resend request fields
     * @return The upstream response body
     * @since 0.0.1
     */
    @Post("/resend")
    HttpResponse<Map<String, Object>> resend(@Body ResendRequest request);

    /**
     * Sends a magic link to the user.
     *
     * @param request Magic link request fields
     * @return The upstream response body
     * @since 0.0.1
     */
    @Post("/magiclink")
    HttpResponse<Map<String, Object>> magicLink(@Body MagicLinkRequest request);

    /**
     * Sends a one-time password to the user.
     *
     * @param request OTP request fields
     * @return The upstream response body
     * @since 0.0.1
     */
    @Post("/otp")
    HttpResponse<Map<String, Object>> requestOtp(@Body OtpRequest request);

    /**
     * Fetches the authenticated user's latest account information.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @return The user
     * @since 0.0.1
     */
    @Get("/user")
    HttpResponse<UserSchema> getUser(@Header("Authorization") String authorization);

    /**
     * Updates properties of the authenticated user.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param request User properties to update
     * @return The updated user
     * @since 0.0.1
     */
    @Put("/user")
    HttpResponse<UserSchema> updateUser(@Header("Authorization") String authorization,
                                        @Body UpdateUserRequest request);

    /**
     * Starts linking an OAuth identity to the authenticated user.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param provider OAuth provider name
     * @param scopes Space-separated OAuth scopes
     * @param redirectTo Optional return URL
     * @param codeChallengeMethod Optional PKCE method
     * @return The upstream redirect response
     * @since 0.0.1
     */
    @Get("/user/identities/authorize")
    HttpResponse<?> authorizeIdentityLink(@Header("Authorization") String authorization,
                                          @QueryValue("provider") String provider,
                                          @QueryValue("scopes") String scopes,
                                          @QueryValue("redirect_to") @Nullable String redirectTo,
                                          @QueryValue("code_challenge_method") @Nullable String codeChallengeMethod);

    /**
     * Unlinks an identity from the authenticated user.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param identityId Identity identifier
     * @return The upstream response body
     * @since 0.0.1
     */
    @Delete("/user/identities/{identityId}")
    HttpResponse<Map<String, Object>> unlinkIdentity(@Header("Authorization") String authorization,
                                                      @PathVariable("identityId") String identityId);

    /**
     * Lists OAuth grants for the authenticated user.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @return The user's grants
     * @since 0.0.1
     */
    @Get("/user/oauth/grants")
    HttpResponse<List<Map<String, Object>>> listUserOAuthGrants(@Header("Authorization") String authorization);

    /**
     * Revokes one OAuth grant for the authenticated user.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param clientId OAuth client identifier
     * @return The upstream response
     * @since 0.0.1
     */
    @Delete("/user/oauth/grants")
    HttpResponse<?> revokeUserOAuthGrant(@Header("Authorization") String authorization,
                                         @QueryValue("client_id") String clientId);

    /**
     * Reauthenticates possession of the user's email address or phone number.
     *
     * <p>GoTrue serves this route with {@code GET} even though the OpenAPI specification documents {@code POST}.</p>
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @return The upstream response body
     * @since 0.0.1
     */
    @Get("/reauthenticate")
    HttpResponse<Map<String, Object>> reauthenticate(@Header("Authorization") String authorization);

    /**
     * Begins enrolling a new MFA factor.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param request Factor enrollment fields
     * @return The factor enrollment response
     * @since 0.0.1
     */
    @Post("/factors")
    HttpResponse<Map<String, Object>> enrollFactor(@Header("Authorization") String authorization,
                                                    @Body EnrollFactorRequest request);

    /**
     * Creates a challenge for an enrolled MFA factor.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param factorId Factor identifier
     * @param request Optional challenge fields, such as the phone channel
     * @return The challenge response
     * @since 0.0.1
     */
    @Post("/factors/{factorId}/challenge")
    HttpResponse<Map<String, Object>> challengeFactor(@Header("Authorization") String authorization,
                                                       @PathVariable("factorId") String factorId,
                                                       @Body ChallengeFactorRequest request);

    /**
     * Verifies a challenge for an enrolled MFA factor.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param factorId Factor identifier
     * @param request Challenge verification fields
     * @return The upgraded token response
     * @since 0.0.1
     */
    @Post("/factors/{factorId}/verify")
    HttpResponse<AccessTokenResponseSchema> verifyFactor(@Header("Authorization") String authorization,
                                                          @PathVariable("factorId") String factorId,
                                                          @Body VerifyFactorRequest request);

    /**
     * Removes an MFA factor from the authenticated user.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param factorId Factor identifier
     * @return The upstream response body
     * @since 0.0.1
     */
    @Delete("/factors/{factorId}")
    HttpResponse<Map<String, Object>> deleteFactor(@Header("Authorization") String authorization,
                                                    @PathVariable("factorId") String factorId);

    /**
     * Gets the authenticated user's MFA recovery-code status.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @return Recovery-code status
     * @since 0.0.1
     */
    @Get("/factors/recovery-codes")
    HttpResponse<MFARecoveryCodesStatusSchema> getRecoveryCodeStatus(@Header("Authorization") String authorization);

    /**
     * Generates a new set of MFA recovery codes.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param request Optional recovery-code factor fields
     * @return The generated recovery codes
     * @since 0.0.1
     */
    @Post("/factors/recovery-codes")
    HttpResponse<MFARecoveryCodesSchema> generateRecoveryCodes(@Header("Authorization") String authorization,
                                                                @Body @Nullable GenerateRecoveryCodesRequest request);

    /**
     * Revokes the authenticated user's MFA recovery codes.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @return The upstream response body
     * @since 0.0.1
     */
    @Delete("/factors/recovery-codes")
    HttpResponse<Map<String, Object>> revokeRecoveryCodes(@Header("Authorization") String authorization);

    /**
     * Verifies a recovery code and upgrades the session to AAL2.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param request Recovery-code verification fields
     * @return The upgraded token response
     * @since 0.0.1
     */
    @Post("/factors/recovery-codes/verify")
    HttpResponse<AccessTokenResponseSchema> verifyRecoveryCode(@Header("Authorization") String authorization,
                                                                @Body VerifyRecoveryCodeRequest request);

    /**
     * Replaces the authenticated user's recovery codes with a new set.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @return The generated recovery codes
     * @since 0.0.1
     */
    @Post("/factors/recovery-codes/regenerate")
    HttpResponse<MFARecoveryCodesSchema> regenerateRecoveryCodes(@Header("Authorization") String authorization);

    /**
     * Handles the OAuth callback and returns its redirect response.
     *
     * @return The upstream redirect response
     * @since 0.0.1
     */
    @Get("/callback")
    HttpResponse<?> oauthCallback();

    /**
     * Handles the POST OAuth callback and returns its redirect response.
     *
     * @return The upstream redirect response
     * @since 0.0.1
     */
    @Post("/callback")
    HttpResponse<?> oauthCallbackPost();

    /**
     * Initiates a single sign-on flow.
     *
     * @param request SSO provider and redirect fields
     * @return The SSO initiation response
     * @since 0.0.1
     */
    @Post("/sso")
    HttpResponse<Map<String, Object>> initiateSso(@Body SsoRequest request);

    /**
     * Retrieves the SAML 2.0 metadata document.
     *
     * <p>GoTrue mounts the SAML routes under {@code /sso}, so this calls {@code /sso/saml/metadata}
     * although the OpenAPI specification lists {@code /saml/metadata}.</p>
     *
     * @param download Whether to request a download response
     * @return The metadata XML
     * @since 0.0.1
     */
    @Get("/sso/saml/metadata")
    HttpResponse<String> getSamlMetadata(@QueryValue("download") @Nullable Boolean download);

    /**
     * Handles a SAML 2.0 assertion consumer service request.
     *
     * @param relayState SAML relay state
     * @param samlArt SAML artifact, when using artifact binding
     * @param samlResponse SAML response, when using HTTP POST binding
     * @return The upstream redirect response
     * @since 0.0.1
     */
    @Post("/sso/saml/acs")
    HttpResponse<?> samlAcs(@QueryValue("RelayState") @Nullable String relayState,
                            @QueryValue("SAMLArt") @Nullable String samlArt,
                            @QueryValue("SAMLResponse") @Nullable String samlResponse);

    /**
     * Invites a user by email.
     *
     * @param request Invitation fields
     * @return The invited user
     * @since 0.0.1
     */
    @Post("/invite")
    HttpResponse<UserSchema> inviteUser(@Body InviteUserRequest request);

    /**
     * Generates a link for an administrative email action.
     *
     * @param request Link generation fields
     * @return The generated link response
     * @since 0.0.1
     */
    @Post("/admin/generate_link")
    HttpResponse<Map<String, Object>> generateAdminLink(@Body GenerateAdminLinkRequest request);

    /**
     * Fetches administrative audit log events.
     *
     * @param page Page number
     * @param perPage Number of events per page
     * @return Audit events
     * @since 0.0.1
     */
    @Get("/admin/audit")
    HttpResponse<List<Map<String, Object>>> getAdminAudit(@QueryValue("page") @Nullable Integer page,
                                                           @QueryValue("per_page") @Nullable Integer perPage);

    /**
     * Fetches a page of administrative user records.
     *
     * @param page Page number
     * @param perPage Number of users per page
     * @return The user listing response
     * @since 0.0.1
     */
    @Get("/admin/users")
    HttpResponse<Map<String, Object>> listAdminUsers(@QueryValue("page") @Nullable Integer page,
                                                      @QueryValue("per_page") @Nullable Integer perPage);

    /**
     * Fetches an administrative user record by identifier.
     *
     * @param userId User identifier
     * @return The user
     * @since 0.0.1
     */
    @Get("/admin/users/{userId}")
    HttpResponse<UserSchema> getAdminUser(@PathVariable("userId") String userId);

    /**
     * Updates an administrative user record.
     *
     * @param userId User identifier
     * @param user User fields to update
     * @return The updated user
     * @since 0.0.1
     */
    @Put("/admin/users/{userId}")
    HttpResponse<UserSchema> updateAdminUser(@PathVariable("userId") String userId,
                                             @Body UserSchema user);

    /**
     * Deletes an administrative user record.
     *
     * @param userId User identifier
     * @return The deleted user
     * @since 0.0.1
     */
    @Delete("/admin/users/{userId}")
    HttpResponse<UserSchema> deleteAdminUser(@PathVariable("userId") String userId);

    /**
     * Lists MFA factors belonging to an administrative user.
     *
     * @param userId User identifier
     * @return The user's factors
     * @since 0.0.1
     */
    @Get("/admin/users/{userId}/factors")
    HttpResponse<List<MFAFactorSchema>> getAdminUserFactors(@PathVariable("userId") String userId);

    /**
     * Updates an MFA factor belonging to an administrative user.
     *
     * @param userId User identifier
     * @param factorId Factor identifier
     * @param request Factor fields to update
     * @return The updated factor
     * @since 0.0.1
     */
    @Put("/admin/users/{userId}/factors/{factorId}")
    HttpResponse<MFAFactorSchema> updateAdminUserFactor(@PathVariable("userId") String userId,
                                                        @PathVariable("factorId") String factorId,
                                                        @Body UpdateAdminUserFactorRequest request);

    /**
     * Removes an MFA factor belonging to an administrative user.
     *
     * @param userId User identifier
     * @param factorId Factor identifier
     * @return The deleted factor
     * @since 0.0.1
     */
    @Delete("/admin/users/{userId}/factors/{factorId}")
    HttpResponse<MFAFactorSchema> deleteAdminUserFactor(@PathVariable("userId") String userId,
                                                        @PathVariable("factorId") String factorId);

    /**
     * Lists registered SSO providers.
     *
     * @return The provider listing
     * @since 0.0.1
     */
    @Get("/admin/sso/providers")
    HttpResponse<Map<String, Object>> listAdminSsoProviders();

    /**
     * Registers an SSO provider.
     *
     * @param request SSO provider configuration
     * @return The registered provider
     * @since 0.0.1
     */
    @Post("/admin/sso/providers")
    HttpResponse<SSOProviderSchema> createAdminSsoProvider(@Body CreateSsoProviderRequest request);

    /**
     * Fetches an SSO provider by identifier.
     *
     * @param ssoProviderId Provider identifier
     * @return The provider
     * @since 0.0.1
     */
    @Get("/admin/sso/providers/{ssoProviderId}")
    HttpResponse<SSOProviderSchema> getAdminSsoProvider(@PathVariable("ssoProviderId") String ssoProviderId);

    /**
     * Updates an SSO provider.
     *
     * @param ssoProviderId Provider identifier
     * @param request Provider fields to update
     * @return The updated provider
     * @since 0.0.1
     */
    @Put("/admin/sso/providers/{ssoProviderId}")
    HttpResponse<SSOProviderSchema> updateAdminSsoProvider(@PathVariable("ssoProviderId") String ssoProviderId,
                                                           @Body UpdateSsoProviderRequest request);

    /**
     * Removes an SSO provider.
     *
     * @param ssoProviderId Provider identifier
     * @return The removed provider
     * @since 0.0.1
     */
    @Delete("/admin/sso/providers/{ssoProviderId}")
    HttpResponse<SSOProviderSchema> deleteAdminSsoProvider(@PathVariable("ssoProviderId") String ssoProviderId);

    /**
     * Lists OAuth clients managed by the administrator.
     *
     * @param page Page number
     * @param perPage Number of clients per page
     * @return The client listing
     * @since 0.0.1
     */
    @Get("/admin/oauth/clients")
    HttpResponse<Map<String, Object>> listAdminOAuthClients(@QueryValue("page") @Nullable Integer page,
                                                             @QueryValue("per_page") @Nullable Integer perPage);

    /**
     * Registers an OAuth client administratively.
     *
     * @param request OAuth client registration fields
     * @return The registered client
     * @since 0.0.1
     */
    @Post("/admin/oauth/clients")
    HttpResponse<OAuthClientSchema> createAdminOAuthClient(@Body OAuthClientRegistrationRequest request);

    /**
     * Fetches an OAuth client by identifier.
     *
     * @param clientId Client identifier
     * @return The OAuth client
     * @since 0.0.1
     */
    @Get("/admin/oauth/clients/{client_id}")
    HttpResponse<OAuthClientSchema> getAdminOAuthClient(@PathVariable("client_id") String clientId);

    /**
     * Updates an OAuth client.
     *
     * @param clientId Client identifier
     * @param request OAuth client fields to update
     * @return The updated client
     * @since 0.0.1
     */
    @Put("/admin/oauth/clients/{client_id}")
    HttpResponse<OAuthClientSchema> updateAdminOAuthClient(@PathVariable("client_id") String clientId,
                                                           @Body OAuthClientUpdateRequest request);

    /**
     * Deletes an OAuth client.
     *
     * @param clientId Client identifier
     * @return The upstream response
     * @since 0.0.1
     */
    @Delete("/admin/oauth/clients/{client_id}")
    HttpResponse<?> deleteAdminOAuthClient(@PathVariable("client_id") String clientId);

    /**
     * Regenerates an OAuth client's secret.
     *
     * @param clientId Client identifier
     * @return The client with its regenerated secret
     * @since 0.0.1
     */
    @Post("/admin/oauth/clients/{client_id}/regenerate_secret")
    HttpResponse<OAuthClientSchema> regenerateAdminOAuthClientSecret(@PathVariable("client_id") String clientId);

    /**
     * Lists custom OAuth and OIDC providers.
     *
     * @param type Optional provider type filter
     * @return The provider listing
     * @since 0.0.1
     */
    @Get("/admin/custom-providers")
    HttpResponse<Map<String, Object>> listCustomOAuthProviders(@QueryValue("type") @Nullable String type);

    /**
     * Creates a custom OAuth or OIDC provider.
     *
     * @param request Provider configuration
     * @return The created provider
     * @since 0.0.1
     */
    @Post("/admin/custom-providers")
    HttpResponse<CustomOAuthProviderSchema> createCustomOAuthProvider(@Body CreateCustomOAuthProviderRequest request);

    /**
     * Fetches a custom OAuth or OIDC provider by identifier.
     *
     * <p>Identifiers carry a {@code custom:} prefix that GoTrue reads verbatim from the path, so the
     * colon is sent unencoded.</p>
     *
     * @param identifier Provider identifier
     * @return The provider
     * @since 0.0.1
     */
    @Get("/admin/custom-providers/{+identifier}")
    HttpResponse<CustomOAuthProviderSchema> getCustomOAuthProvider(@PathVariable("identifier") String identifier);

    /**
     * Updates a custom OAuth or OIDC provider.
     *
     * @param identifier Provider identifier
     * @param request Provider fields to update
     * @return The updated provider
     * @since 0.0.1
     */
    @Put("/admin/custom-providers/{+identifier}")
    HttpResponse<CustomOAuthProviderSchema> updateCustomOAuthProvider(@PathVariable("identifier") String identifier,
                                                                      @Body UpdateCustomOAuthProviderRequest request);

    /**
     * Deletes a custom OAuth or OIDC provider.
     *
     * @param identifier Provider identifier
     * @return The upstream response
     * @since 0.0.1
     */
    @Delete("/admin/custom-providers/{+identifier}")
    HttpResponse<?> deleteCustomOAuthProvider(@PathVariable("identifier") String identifier);

    /**
     * Registers an OAuth client dynamically.
     *
     * @param request OAuth client registration fields
     * @return The registered client
     * @since 0.0.1
     */
    @Post("/oauth/clients/register")
    HttpResponse<OAuthClientSchema> registerOAuthClient(@Body OAuthClientRegistrationRequest request);

    /**
     * Exchanges an OAuth authorization code or refresh token.
     *
     * @param request Form fields for the OAuth token grant
     * @return The token response
     * @since 0.0.1
     */
    @Post("/oauth/token")
    @Produces(MediaType.APPLICATION_FORM_URLENCODED)
    HttpResponse<Map<String, Object>> oauthToken(@Body Map<String, String> request);

    /**
     * Exchanges an OAuth authorization code or refresh token using a typed request.
     *
     * @param request Typed OAuth token request
     * @return The token response
     * @since 0.0.1
     */
    default HttpResponse<Map<String, Object>> oauthToken(OAuthTokenRequest request) {
        return oauthToken(request.toMap());
    }

    /**
     * Starts an OAuth authorization flow.
     *
     * @param responseType OAuth response type
     * @param clientId OAuth client identifier
     * @param redirectUri Client redirect URI
     * @param scope Optional requested scope
     * @param state Optional CSRF state
     * @param codeChallenge PKCE code challenge
     * @param codeChallengeMethod PKCE method
     * @return The upstream authorization response
     * @since 0.0.1
     */
    @Get("/oauth/authorize")
    HttpResponse<?> authorizeOAuthClient(@QueryValue("response_type") String responseType,
                                         @QueryValue("client_id") String clientId,
                                         @QueryValue("redirect_uri") String redirectUri,
                                         @QueryValue("scope") @Nullable String scope,
                                         @QueryValue("state") @Nullable String state,
                                         @QueryValue("code_challenge") String codeChallenge,
                                         @QueryValue("code_challenge_method") String codeChallengeMethod);

    /**
     * Gets details of an OAuth authorization for the authenticated user.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param authorizationId Authorization identifier
     * @return The authorization details
     * @since 0.0.1
     */
    @Get("/oauth/authorizations/{authorization_id}")
    HttpResponse<Map<String, Object>> getOAuthAuthorization(@Header("Authorization") String authorization,
                                                             @PathVariable("authorization_id") String authorizationId);

    /**
     * Approves or denies an OAuth authorization.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param authorizationId Authorization identifier
     * @param request Consent decision fields
     * @return The updated authorization
     * @since 0.0.1
     */
    @Post("/oauth/authorizations/{authorization_id}/consent")
    HttpResponse<Map<String, Object>> consentOAuthAuthorization(@Header("Authorization") String authorization,
                                                                 @PathVariable("authorization_id") String authorizationId,
                                                                 @Body ConsentOAuthAuthorizationRequest request);

    /**
     * Checks the health of the Auth service.
     *
     * @return The health response
     * @since 0.0.1
     */
    @Get("/health")
    HttpResponse<Map<String, Object>> health();

    /**
     * Retrieves public Auth server settings.
     *
     * @return The public settings
     * @since 0.0.1
     */
    @Get("/settings")
    HttpResponse<Map<String, Object>> settings();
}
