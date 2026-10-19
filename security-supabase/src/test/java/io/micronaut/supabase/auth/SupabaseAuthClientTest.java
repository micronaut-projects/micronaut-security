package io.micronaut.supabase.auth;

import io.micronaut.context.ApplicationContext;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
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
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.test.support.TestPropertyProvider;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises every route of {@link SupabaseAuthClient} against a real Supabase Auth (GoTrue) server
 * started with Testcontainers. Each test creates its own users so tests do not depend on each other.
 * Administrative routes authenticate through the secret key configured in {@link Supabase#getProperties()}.
 */
@Testcontainers(disabledWithoutDocker = true)
@MicronautTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SupabaseAuthClientTest implements TestPropertyProvider {
    private static final Argument<Map<String, Object>> MAP_ARGUMENT = Argument.mapOf(String.class, Object.class);
    private static final String PASSWORD = Supabase.TEST_PASSWORD;
    private static final String REDIRECT_URI = Supabase.SITE_URL + "/callback";
    private static final SecureRandom RANDOM = new SecureRandom();

    @Inject
    SupabaseAuthClient client;

    @Override
    public @NonNull Map<String, String> getProperties() {
        return Supabase.getProperties();
    }

    // ------------------------------------------------------------------ server information

    @Test
    void healthReportsGoTrue() {
        HttpResponse<Map<String, Object>> response = client.health();

        assertEquals(HttpStatus.OK, response.getStatus());
        Map<String, Object> body = response.body();
        assertEquals("GoTrue", body.get("name"));
        assertNotNull(body.get("version"));
    }

    @Test
    void settingsExposeEnabledProviders() {
        HttpResponse<Map<String, Object>> response = client.settings();

        assertEquals(HttpStatus.OK, response.getStatus());
        Map<String, Object> body = response.body();
        assertEquals(false, body.get("disable_signup"));
        Map<String, Object> external = map(body.get("external"));
        assertEquals(true, external.get("email"));
        assertEquals(true, external.get("github"));
        assertEquals(false, external.get("gitlab"));
    }

    // ------------------------------------------------------------------ signup and token

    @Test
    void signupReturnsSessionForConfirmedUser() {
        String email = uniqueEmail("signup");

        HttpResponse<Map<String, Object>> response = client.signup(null, signupRequest(email));

        assertEquals(HttpStatus.OK, response.getStatus());
        Map<String, Object> body = response.body();
        assertEquals("bearer", body.get("token_type"));
        assertNotNull(body.get("access_token"));
        assertNotNull(body.get("refresh_token"));
        assertEquals(email, map(body.get("user")).get("email"));
    }

    @Test
    void signupWithRedirectToReturnsSession() {
        HttpResponse<Map<String, Object>> response = client.signup(Supabase.SITE_URL + "/welcome", signupRequest(uniqueEmail("signup-redirect")));

        assertEquals(HttpStatus.OK, response.getStatus());
        assertNotNull(response.body().get("access_token"));
    }

    @Test
    void signupRejectsWeakPassword() {
        SignupRequest request = new SignupRequest(uniqueEmail("weak"), null, "123", null, null, null, null, null);

        assertError(HttpStatus.UNPROCESSABLE_ENTITY, "weak_password", () -> client.signup(null, request));
    }

    @Test
    void tokenWithPasswordGrantReturnsSession() {
        String email = uniqueEmail("password-grant");
        client.signup(null, signupRequest(email));

        HttpResponse<AccessTokenResponseSchema> response = client.token("password", passwordGrant(email, PASSWORD));

        assertEquals(HttpStatus.OK, response.getStatus());
        AccessTokenResponseSchema session = response.body();
        assertEquals("bearer", session.tokenType());
        assertNotNull(session.accessToken());
        assertNotNull(session.refreshToken());
        assertEquals(3600, session.expiresIn());
        assertEquals(email, session.user().email());
        assertEquals(Supabase.JWT_ISSUER, claim(session.accessToken(), "iss"));
        assertEquals("authenticated", claim(session.accessToken(), "aud"));
        assertEquals("authenticated", claim(session.accessToken(), "role"));
        assertEquals("aal1", claim(session.accessToken(), "aal"));
        assertEquals(session.user().id(), claim(session.accessToken(), "sub"));
    }

    @Test
    void tokenWithRefreshTokenGrantRotatesTokens() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("refresh-grant"));
        TokenRequest request = new TokenRequest(session.refreshToken(), null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null);

        HttpResponse<AccessTokenResponseSchema> response = client.token("refresh_token", request);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertNotNull(response.body().accessToken());
        assertNotEquals(session.refreshToken(), response.body().refreshToken());
    }

    @Test
    void tokenRejectsWrongPassword() {
        String email = uniqueEmail("wrong-password");
        client.signup(null, signupRequest(email));

        assertError(HttpStatus.BAD_REQUEST, "invalid_credentials", () -> client.token("password", passwordGrant(email, "not-the-password")));
    }

    @Test
    void tokenRejectsUnsupportedGrantType() {
        assertError(HttpStatus.BAD_REQUEST, "invalid_credentials", () -> client.token("client_credentials", passwordGrant(uniqueEmail("grant"), PASSWORD)));
    }

    // ------------------------------------------------------------------ logout

    @Test
    void logoutInvalidatesSession() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("logout"));

        HttpResponse<?> response = client.logout(bearer(session), "global");

        assertEquals(HttpStatus.NO_CONTENT, response.getStatus());
        assertError(HttpStatus.FORBIDDEN, "session_not_found", () -> client.getUser(bearer(session)));
    }

    @Test
    void logoutWithLocalScopeKeepsOtherSessions() {
        String email = uniqueEmail("logout-local");
        AccessTokenResponseSchema first = signUpAndLogin(email);
        AccessTokenResponseSchema second = client.token("password", passwordGrant(email, PASSWORD)).body();

        assertEquals(HttpStatus.NO_CONTENT, client.logout(bearer(first), "local").getStatus());

        assertEquals(HttpStatus.OK, client.getUser(bearer(second)).getStatus());
    }

    @Test
    void logoutRejectsUnsupportedScope() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("logout-scope"));

        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.logout(bearer(session), "everything"));
    }

    @Test
    void logoutRejectsInvalidToken() {
        assertError(HttpStatus.FORBIDDEN, "bad_jwt", () -> client.logout("Bearer not-a-jwt", null));
    }

    // ------------------------------------------------------------------ verify

    @Test
    void verifyWithTokenHashReturnsSession() {
        String email = uniqueEmail("verify-post");
        client.signup(null, signupRequest(email));
        String hashedToken = string(generateMagicLink(email).get("hashed_token"));

        HttpResponse<AccessTokenResponseSchema> response = client.verify(new VerifyRequest("magiclink", null, hashedToken, null, null, null));

        assertEquals(HttpStatus.OK, response.getStatus());
        assertNotNull(response.body().accessToken());
        assertEquals(email, response.body().user().email());
    }

    @Test
    void verifyWithEmailOtpReturnsSession() {
        String email = uniqueEmail("verify-otp");
        client.signup(null, signupRequest(email));
        String otp = string(generateMagicLink(email).get("email_otp"));

        HttpResponse<AccessTokenResponseSchema> response = client.verify(new VerifyRequest("magiclink", otp, null, email, null, null));

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(email, response.body().user().email());
    }

    @Test
    void verifyRejectsUnknownTokenHash() {
        assertError(HttpStatus.FORBIDDEN, "otp_expired", () -> client.verify(new VerifyRequest("magiclink", null, "unknown-token-hash", null, null, null)));
    }

    @Test
    void verifyLinkRedirectsToSiteWithSession() {
        String email = uniqueEmail("verify-get");
        client.signup(null, signupRequest(email));
        String hashedToken = string(generateMagicLink(email).get("hashed_token"));

        HttpResponse<?> response = client.verifyLink(hashedToken, "magiclink", null);

        assertEquals(HttpStatus.SEE_OTHER, response.getStatus());
        String location = location(response);
        assertTrue(location.startsWith(Supabase.SITE_URL), location);
        assertTrue(location.contains("access_token="), location);
    }

    @Test
    void verifyLinkWithUnknownTokenRedirectsWithError() {
        HttpResponse<?> response = client.verifyLink("unknown-token", "magiclink", Supabase.SITE_URL + "/login");

        assertEquals(HttpStatus.SEE_OTHER, response.getStatus());
        String location = location(response);
        assertTrue(location.startsWith(Supabase.SITE_URL + "/login"), location);
        assertTrue(location.contains("error_code=otp_expired"), location);
    }

    // ------------------------------------------------------------------ external providers

    @Test
    void authorizeProviderRedirectsToProvider() {
        HttpResponse<?> response = client.authorizeProvider("github", "", null, Supabase.SITE_URL + "/after", null);

        assertEquals(HttpStatus.FOUND, response.getStatus());
        String location = location(response);
        assertTrue(location.startsWith("https://github.com/login/oauth/authorize"), location);
        assertTrue(location.contains("client_id=" + Supabase.GITHUB_CLIENT_ID), location);
    }

    @Test
    void authorizeProviderRejectsDisabledProvider() {
        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.authorizeProvider("gitlab", "", null, null, null));
    }

    @Test
    void oauthCallbackWithoutStateRedirectsWithError() {
        HttpResponse<?> response = client.oauthCallback();

        assertEquals(HttpStatus.SEE_OTHER, response.getStatus());
        String location = location(response);
        assertTrue(location.startsWith(Supabase.SITE_URL), location);
        assertTrue(location.contains("error="), location);
    }

    @Test
    void oauthCallbackPostWithoutStateRedirectsWithError() {
        HttpResponse<?> response = client.oauthCallbackPost();

        assertEquals(HttpStatus.SEE_OTHER, response.getStatus());
        String location = location(response);
        assertTrue(location.startsWith(Supabase.SITE_URL), location);
        assertTrue(location.contains("error="), location);
    }

    // ------------------------------------------------------------------ passwordless email flows

    @Test
    void recoverSendsRecoveryEmail() {
        String email = uniqueEmail("recover");
        client.signup(null, signupRequest(email));

        HttpResponse<Map<String, Object>> response = client.recover(new RecoverRequest(email, null, null, null));

        assertEquals(HttpStatus.OK, response.getStatus());
        assertTrue(response.body().isEmpty());
    }

    @Test
    void recoverRejectsMissingEmail() {
        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.recover(new RecoverRequest("", null, null, null)));
    }

    @Test
    void resendSendsSignupConfirmation() {
        String email = uniqueEmail("resend");
        client.signup(null, signupRequest(email));

        HttpResponse<Map<String, Object>> response = client.resend(new ResendRequest(email, null, "signup", null));

        assertEquals(HttpStatus.OK, response.getStatus());
    }

    @Test
    void resendRejectsMissingType() {
        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.resend(new ResendRequest(uniqueEmail("resend-type"), null, null, null)));
    }

    @Test
    void magicLinkSendsEmail() {
        String email = uniqueEmail("magiclink");
        client.signup(null, signupRequest(email));

        HttpResponse<Map<String, Object>> response = client.magicLink(new MagicLinkRequest(email, null, null));

        assertEquals(HttpStatus.OK, response.getStatus());
    }

    @Test
    void magicLinkRejectsMissingEmail() {
        assertError(HttpStatus.UNPROCESSABLE_ENTITY, "validation_failed", () -> client.magicLink(new MagicLinkRequest("", null, null)));
    }

    @Test
    void requestOtpByEmailCreatesUser() {
        String email = uniqueEmail("otp");

        HttpResponse<Map<String, Object>> response = client.requestOtp(new OtpRequest(email, null, null, true, Map.of("source", "test"), null, null, null));

        assertEquals(HttpStatus.OK, response.getStatus());
        UserSchema user = findAdminUserByEmail(email);
        assertNotNull(user, "OTP request should have created the user");
    }

    @Test
    void requestOtpRejectsPhoneWithoutSmsProvider() {
        assertError(HttpStatus.BAD_REQUEST, "phone_provider_disabled", () -> client.requestOtp(new OtpRequest(null, "+15555550100", null, null, null, null, null, null)));
    }

    @Test
    void requestOtpRejectsEmailAndPhoneTogether() {
        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.requestOtp(new OtpRequest(uniqueEmail("otp-both"), "+15555550100", null, null, null, null, null, null)));
    }

    // ------------------------------------------------------------------ user

    @Test
    void getUserReturnsAuthenticatedUser() {
        String email = uniqueEmail("get-user");
        AccessTokenResponseSchema session = signUpAndLogin(email);

        HttpResponse<UserSchema> response = client.getUser(bearer(session));

        assertEquals(HttpStatus.OK, response.getStatus());
        UserSchema user = response.body();
        assertEquals(email, user.email());
        assertEquals("authenticated", user.role());
        assertNotNull(user.emailConfirmedAt());
        assertEquals(1, user.identities().size());
        assertEquals("email", user.identities().getFirst().provider());
    }

    @Test
    void getUserRejectsMissingBearer() {
        assertError(HttpStatus.UNAUTHORIZED, "no_authorization", () -> client.getUser("Basic abc"));
    }

    @Test
    void updateUserChangesMetadata() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("update-user"));
        UpdateUserRequest request = new UpdateUserRequest(null, null, null, null, Map.of("display_name", "Alice"), null, null);

        HttpResponse<UserSchema> response = client.updateUser(bearer(session), request);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("Alice", response.body().userMetadata().get("display_name"));
    }

    @Test
    void updateUserRejectsWeakPassword() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("update-weak"));
        UpdateUserRequest request = new UpdateUserRequest(null, null, "123", null, null, null, null);

        assertError(HttpStatus.UNPROCESSABLE_ENTITY, "weak_password", () -> client.updateUser(bearer(session), request));
    }

    @Test
    void reauthenticateSendsNonce() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("reauthenticate"));

        HttpResponse<Map<String, Object>> response = client.reauthenticate(bearer(session));

        assertEquals(HttpStatus.OK, response.getStatus());
        assertNotNull(client.getUser(bearer(session)).body().reauthenticationSentAt());
    }

    @Test
    void reauthenticateRejectsMissingBearer() {
        assertError(HttpStatus.UNAUTHORIZED, "no_authorization", () -> client.reauthenticate(""));
    }

    // ------------------------------------------------------------------ identities

    @Test
    void authorizeIdentityLinkRedirectsToProvider() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("link-identity"));

        HttpResponse<?> response = client.authorizeIdentityLink(bearer(session), "github", "", null, null);

        assertEquals(HttpStatus.FOUND, response.getStatus());
        assertTrue(location(response).startsWith("https://github.com/login/oauth/authorize"), location(response));
    }

    @Test
    void authorizeIdentityLinkRejectsDisabledProvider() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("link-disabled"));

        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.authorizeIdentityLink(bearer(session), "gitlab", "", null, null));
    }

    @Test
    void unlinkIdentityRejectsRemovingLastIdentity() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("unlink"));
        String identityId = client.getUser(bearer(session)).body().identities().getFirst().identityId();

        assertError(HttpStatus.UNPROCESSABLE_ENTITY, "single_identity_not_deletable", () -> client.unlinkIdentity(bearer(session), identityId));
    }

    @Test
    void unlinkIdentityRejectsMalformedIdentifier() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("unlink-malformed"));

        assertError(HttpStatus.NOT_FOUND, "validation_failed", () -> client.unlinkIdentity(bearer(session), "not-a-uuid"));
    }

    // ------------------------------------------------------------------ MFA factors

    @Test
    void enrollFactorReturnsTotpSecret() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("enroll"));

        HttpResponse<Map<String, Object>> response = client.enrollFactor(bearer(session), new EnrollFactorRequest("totp", "Authenticator", "micronaut-security", null));

        assertEquals(HttpStatus.OK, response.getStatus());
        Map<String, Object> factor = response.body();
        assertEquals("totp", factor.get("type"));
        assertEquals("Authenticator", factor.get("friendly_name"));
        assertNotNull(factor.get("id"));
        Map<String, Object> totp = map(factor.get("totp"));
        assertNotNull(totp.get("secret"));
        assertTrue(string(totp.get("uri")).startsWith("otpauth://totp/"), string(totp.get("uri")));
    }

    @Test
    void enrollFactorRejectsPhoneWithoutSmsProvider() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("enroll-phone"));

        assertClientError(() -> client.enrollFactor(bearer(session), new EnrollFactorRequest("phone", "Phone", null, "+15555550100")));
    }

    @Test
    void challengeFactorReturnsChallenge() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("challenge"));
        Map<String, Object> factor = enrollTotp(session);

        HttpResponse<Map<String, Object>> response = client.challengeFactor(bearer(session), string(factor.get("id")), new ChallengeFactorRequest(null));

        assertEquals(HttpStatus.OK, response.getStatus());
        assertNotNull(response.body().get("id"));
        assertNotNull(response.body().get("expires_at"));
    }

    @Test
    void challengeFactorRejectsUnknownFactor() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("challenge-unknown"));

        assertError(HttpStatus.NOT_FOUND, "mfa_factor_not_found", () -> client.challengeFactor(bearer(session), UUID.randomUUID().toString(), new ChallengeFactorRequest(null)));
    }

    @Test
    void verifyFactorUpgradesSessionToAal2() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("verify-factor"));
        Map<String, Object> factor = enrollTotp(session);
        String factorId = string(factor.get("id"));
        String challengeId = string(client.challengeFactor(bearer(session), factorId, new ChallengeFactorRequest(null)).body().get("id"));
        String code = Supabase.totpCode(string(map(factor.get("totp")).get("secret")));

        HttpResponse<AccessTokenResponseSchema> response = client.verifyFactor(bearer(session), factorId, new VerifyFactorRequest(challengeId, code, null));

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("aal2", claim(response.body().accessToken(), "aal"));
        assertEquals("verified", response.body().user().factors().getFirst().status());
    }

    @Test
    void verifyFactorRejectsWrongCode() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("verify-wrong"));
        Map<String, Object> factor = enrollTotp(session);
        String factorId = string(factor.get("id"));
        String challengeId = string(client.challengeFactor(bearer(session), factorId, new ChallengeFactorRequest(null)).body().get("id"));

        assertError(HttpStatus.UNPROCESSABLE_ENTITY, "mfa_verification_failed", () -> client.verifyFactor(bearer(session), factorId, new VerifyFactorRequest(challengeId, "000000", null)));
    }

    @Test
    void deleteFactorUnenrollsFactor() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("delete-factor"));
        Map<String, Object> factor = enrollTotp(session);
        String factorId = string(factor.get("id"));

        HttpResponse<Map<String, Object>> response = client.deleteFactor(bearer(session), factorId);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(factorId, response.body().get("id"));
        assertTrue(client.getUser(bearer(session)).body().factors() == null || client.getUser(bearer(session)).body().factors().isEmpty());
    }

    @Test
    void deleteFactorRejectsVerifiedFactorWithAal1Session() {
        String email = uniqueEmail("delete-verified");
        AccessTokenResponseSchema session = signUpAndLogin(email);
        Map<String, Object> factor = enrollTotp(session);
        verifyTotp(session, factor);
        AccessTokenResponseSchema aal1 = client.token("password", passwordGrant(email, PASSWORD)).body();

        assertError(HttpStatus.UNPROCESSABLE_ENTITY, "insufficient_aal", () -> client.deleteFactor(bearer(aal1), string(factor.get("id"))));
    }

    // ------------------------------------------------------------------ MFA recovery codes

    @Test
    void generateRecoveryCodesReturnsCodes() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("recovery-generate"));
        AccessTokenResponseSchema aal2 = verifyTotp(session, enrollTotp(session));

        HttpResponse<MFARecoveryCodesSchema> response = client.generateRecoveryCodes(bearer(aal2), new GenerateRecoveryCodesRequest("Backup codes"));

        assertEquals(HttpStatus.OK, response.getStatus());
        MFARecoveryCodesSchema codes = response.body();
        assertEquals("recovery_code", codes.type());
        assertEquals("Backup codes", codes.friendlyName());
        assertEquals(10, codes.total());
        assertEquals(10, codes.codes().size());
    }

    @Test
    void generateRecoveryCodesRejectsAal1Session() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("recovery-aal1"));
        enrollTotp(session);

        assertError(HttpStatus.FORBIDDEN, "insufficient_aal", () -> client.generateRecoveryCodes(bearer(session), null));
    }

    @Test
    void getRecoveryCodeStatusReportsRemainingCodes() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("recovery-status"));
        AccessTokenResponseSchema aal2 = verifyTotp(session, enrollTotp(session));
        MFARecoveryCodesSchema codes = client.generateRecoveryCodes(bearer(aal2), null).body();

        HttpResponse<MFARecoveryCodesStatusSchema> response = client.getRecoveryCodeStatus(bearer(aal2));

        assertEquals(HttpStatus.OK, response.getStatus());
        MFARecoveryCodesStatusSchema status = response.body();
        assertEquals(codes.id(), status.id());
        assertEquals("recovery_code", status.type());
        assertEquals(10, status.total());
        assertEquals(10, status.remaining());
    }

    @Test
    void getRecoveryCodeStatusWithoutEnrollmentIsNotFound() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("recovery-status-none"));

        assertError(HttpStatus.NOT_FOUND, "mfa_factor_not_found", () -> client.getRecoveryCodeStatus(bearer(session)));
    }

    @Test
    void verifyRecoveryCodeUpgradesSessionAndConsumesCode() {
        String email = uniqueEmail("recovery-verify");
        AccessTokenResponseSchema session = signUpAndLogin(email);
        AccessTokenResponseSchema aal2 = verifyTotp(session, enrollTotp(session));
        MFARecoveryCodesSchema codes = client.generateRecoveryCodes(bearer(aal2), null).body();
        AccessTokenResponseSchema aal1 = client.token("password", passwordGrant(email, PASSWORD)).body();

        HttpResponse<AccessTokenResponseSchema> response = client.verifyRecoveryCode(bearer(aal1), new VerifyRecoveryCodeRequest(codes.codes().getFirst()));

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("aal2", claim(response.body().accessToken(), "aal"));
        assertEquals(9, client.getRecoveryCodeStatus(bearer(response.body())).body().remaining());
    }

    @Test
    void verifyRecoveryCodeRejectsUnknownCode() {
        String email = uniqueEmail("recovery-verify-wrong");
        AccessTokenResponseSchema session = signUpAndLogin(email);
        AccessTokenResponseSchema aal2 = verifyTotp(session, enrollTotp(session));
        client.generateRecoveryCodes(bearer(aal2), null);
        AccessTokenResponseSchema aal1 = client.token("password", passwordGrant(email, PASSWORD)).body();

        assertError(HttpStatus.UNPROCESSABLE_ENTITY, "mfa_verification_failed", () -> client.verifyRecoveryCode(bearer(aal1), new VerifyRecoveryCodeRequest("0000-0000-0000-0000")));
    }

    @Test
    void regenerateRecoveryCodesReplacesCodes() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("recovery-regenerate"));
        AccessTokenResponseSchema aal2 = verifyTotp(session, enrollTotp(session));
        MFARecoveryCodesSchema original = client.generateRecoveryCodes(bearer(aal2), null).body();

        HttpResponse<MFARecoveryCodesSchema> response = client.regenerateRecoveryCodes(bearer(aal2));

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(10, response.body().codes().size());
        assertFalse(response.body().codes().contains(original.codes().getFirst()));
    }

    @Test
    void regenerateRecoveryCodesRejectsAal1Session() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("recovery-regenerate-aal1"));

        assertError(HttpStatus.FORBIDDEN, "insufficient_aal", () -> client.regenerateRecoveryCodes(bearer(session)));
    }

    @Test
    void revokeRecoveryCodesRemovesEnrollment() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("recovery-revoke"));
        AccessTokenResponseSchema aal2 = verifyTotp(session, enrollTotp(session));
        client.generateRecoveryCodes(bearer(aal2), null);

        HttpResponse<Map<String, Object>> response = client.revokeRecoveryCodes(bearer(aal2));

        assertEquals(HttpStatus.OK, response.getStatus());
        assertError(HttpStatus.NOT_FOUND, "mfa_factor_not_found", () -> client.getRecoveryCodeStatus(bearer(aal2)));
    }

    @Test
    void revokeRecoveryCodesRejectsAal1Session() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("recovery-revoke-aal1"));

        assertError(HttpStatus.FORBIDDEN, "insufficient_aal", () -> client.revokeRecoveryCodes(bearer(session)));
    }

    // ------------------------------------------------------------------ invite and admin links

    @Test
    void inviteUserCreatesInvitedUser() {
        String email = uniqueEmail("invite");

        HttpResponse<UserSchema> response = client.inviteUser(new InviteUserRequest(email, Map.of("team", "security")));

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(email, response.body().email());
        assertNotNull(response.body().id());
        assertEquals("security", response.body().userMetadata().get("team"));
    }

    @Test
    void inviteUserRejectsExistingEmail() {
        String email = uniqueEmail("invite-existing");
        client.signup(null, signupRequest(email));

        assertError(HttpStatus.UNPROCESSABLE_ENTITY, "email_exists", () -> client.inviteUser(new InviteUserRequest(email, null)));
    }

    @Test
    void generateAdminLinkReturnsMagicLink() {
        String email = uniqueEmail("generate-link");
        client.signup(null, signupRequest(email));

        HttpResponse<Map<String, Object>> response = client.generateAdminLink(new GenerateAdminLinkRequest("magiclink", email, null, null, null, Supabase.SITE_URL + "/magic"));

        assertEquals(HttpStatus.OK, response.getStatus());
        Map<String, Object> link = response.body();
        assertEquals("magiclink", link.get("verification_type"));
        assertEquals(Supabase.SITE_URL + "/magic", link.get("redirect_to"));
        assertNotNull(link.get("hashed_token"));
        assertNotNull(link.get("email_otp"));
        assertTrue(string(link.get("action_link")).contains("/verify?token="), string(link.get("action_link")));
        assertEquals(email, link.get("email"));
    }

    @Test
    void generateAdminLinkRejectsUnknownType() {
        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.generateAdminLink(new GenerateAdminLinkRequest("teleport", uniqueEmail("bad-link"), null, null, null, null)));
    }

    // ------------------------------------------------------------------ admin credentials

    @Test
    void adminRouteWithoutSecretKeyIsRejected() {
        Map<String, Object> properties = new HashMap<>(Supabase.getProperties());
        properties.remove(Supabase.SECRET_KEY_PROPERTY);
        try (ApplicationContext context = ApplicationContext.run(properties)) {
            SupabaseAuthClient anonymousClient = context.getBean(SupabaseAuthClient.class);

            assertError(HttpStatus.UNAUTHORIZED, "no_authorization", () -> anonymousClient.listAdminUsers(null, null));
        }
    }

    @Test
    void adminRouteWithUserTokenAsSecretKeyIsRejected() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("not-admin"));
        Map<String, Object> properties = new HashMap<>(Supabase.getProperties());
        properties.put(Supabase.SECRET_KEY_PROPERTY, session.accessToken());
        try (ApplicationContext context = ApplicationContext.run(properties)) {
            SupabaseAuthClient userClient = context.getBean(SupabaseAuthClient.class);

            assertError(HttpStatus.FORBIDDEN, "not_admin", () -> userClient.listAdminUsers(null, null));
        }
    }

    // ------------------------------------------------------------------ admin audit and users

    @Test
    void getAdminAuditListsEntries() {
        client.signup(null, signupRequest(uniqueEmail("audit")));

        HttpResponse<List<Map<String, Object>>> response = client.getAdminAudit(1, 5);

        assertEquals(HttpStatus.OK, response.getStatus());
        List<Map<String, Object>> entries = response.body();
        assertFalse(entries.isEmpty());
        assertTrue(entries.size() <= 5);
        assertNotNull(map(entries.getFirst().get("payload")).get("action"));
    }

    @Test
    void listAdminUsersReturnsPage() {
        client.signup(null, signupRequest(uniqueEmail("list-users")));

        HttpResponse<Map<String, Object>> response = client.listAdminUsers(1, 3);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("authenticated", response.body().get("aud"));
        List<?> users = (List<?>) response.body().get("users");
        assertFalse(users.isEmpty());
        assertTrue(users.size() <= 3);
    }

    @Test
    void getAdminUserReturnsUser() {
        String email = uniqueEmail("admin-get");
        String userId = signUpAndLogin(email).user().id();

        HttpResponse<UserSchema> response = client.getAdminUser(userId);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(userId, response.body().id());
        assertEquals(email, response.body().email());
    }

    @Test
    void getAdminUserRejectsUnknownUser() {
        assertError(HttpStatus.NOT_FOUND, "user_not_found", () -> client.getAdminUser(UUID.randomUUID().toString()));
    }

    @Test
    void updateAdminUserChangesAppMetadata() {
        String userId = signUpAndLogin(uniqueEmail("admin-update")).user().id();
        UserSchema update = new UserSchema(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            Map.of("plan", "pro"), Map.of("nickname", "ally"), null, null, null, null, null, null, null);

        HttpResponse<UserSchema> response = client.updateAdminUser(userId, update);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("pro", response.body().appMetadata().get("plan"));
        assertEquals("ally", response.body().userMetadata().get("nickname"));
    }

    @Test
    void deleteAdminUserRemovesUser() {
        String userId = signUpAndLogin(uniqueEmail("admin-delete")).user().id();

        HttpResponse<UserSchema> response = client.deleteAdminUser(userId);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertError(HttpStatus.NOT_FOUND, "user_not_found", () -> client.getAdminUser(userId));
    }

    // ------------------------------------------------------------------ admin user factors

    @Test
    void getAdminUserFactorsListsEnrolledFactors() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("admin-factors"));
        Map<String, Object> factor = enrollTotp(session);

        HttpResponse<List<MFAFactorSchema>> response = client.getAdminUserFactors(session.user().id());

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(1, response.body().size());
        assertEquals(factor.get("id"), response.body().getFirst().id());
        assertEquals("totp", response.body().getFirst().factorType());
        assertEquals("unverified", response.body().getFirst().status());
    }

    @Test
    void getAdminUserFactorsRejectsUnknownUser() {
        assertError(HttpStatus.NOT_FOUND, "user_not_found", () -> client.getAdminUserFactors(UUID.randomUUID().toString()));
    }

    @Test
    void updateAdminUserFactorReturnsFactor() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("admin-factor-update"));
        String factorId = string(enrollTotp(session).get("id"));

        HttpResponse<MFAFactorSchema> response = client.updateAdminUserFactor(session.user().id(), factorId, new UpdateAdminUserFactorRequest());

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(factorId, response.body().id());
        assertEquals("Authenticator", response.body().friendlyName());
    }

    @Test
    void updateAdminUserFactorRejectsUnknownFactor() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("admin-factor-update-unknown"));

        assertError(HttpStatus.NOT_FOUND, "mfa_factor_not_found", () -> client.updateAdminUserFactor(session.user().id(), UUID.randomUUID().toString(), new UpdateAdminUserFactorRequest()));
    }

    @Test
    void deleteAdminUserFactorRemovesFactor() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("admin-factor-delete"));
        String factorId = string(enrollTotp(session).get("id"));

        HttpResponse<MFAFactorSchema> response = client.deleteAdminUserFactor(session.user().id(), factorId);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(factorId, response.body().id());
        assertTrue(client.getAdminUserFactors(session.user().id()).body().isEmpty());
    }

    @Test
    void deleteAdminUserFactorRejectsUnknownFactor() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("admin-factor-delete-unknown"));

        assertError(HttpStatus.NOT_FOUND, "mfa_factor_not_found", () -> client.deleteAdminUserFactor(session.user().id(), UUID.randomUUID().toString()));
    }

    // ------------------------------------------------------------------ SAML SSO

    @Test
    void getSamlMetadataReturnsServiceProviderMetadata() {
        HttpResponse<String> response = client.getSamlMetadata(null);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertTrue(response.getContentType().orElseThrow().toString().contains("xml"));
        assertTrue(response.body().contains("EntityDescriptor"), response.body());
        assertTrue(response.body().contains("SPSSODescriptor"), response.body());
        assertTrue(response.getHeaders().get(HttpHeaders.CONTENT_DISPOSITION) == null);
    }

    @Test
    void getSamlMetadataWithDownloadSetsAttachmentDisposition() {
        HttpResponse<String> response = client.getSamlMetadata(true);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("attachment; filename=\"metadata.xml\"", response.getHeaders().get(HttpHeaders.CONTENT_DISPOSITION));
    }

    @Test
    void initiateSsoByDomainReturnsIdentityProviderUrl() {
        String domain = uniqueDomain("sso");
        SSOProviderSchema provider = createSsoProvider(domain);

        HttpResponse<Map<String, Object>> response = client.initiateSso(new SsoRequest(domain, null, null, true, null, null, null));

        assertEquals(HttpStatus.OK, response.getStatus());
        String url = string(response.body().get("url"));
        assertTrue(url.startsWith(provider.saml().entityId() + "/sso?SAMLRequest="), url);
    }

    @Test
    void initiateSsoByProviderIdRedirectsToIdentityProvider() {
        SSOProviderSchema provider = createSsoProvider(uniqueDomain("sso-id"));

        HttpResponse<Map<String, Object>> response = client.initiateSso(new SsoRequest(null, provider.id(), null, true, null, null, null));

        assertEquals(HttpStatus.OK, response.getStatus());
        assertTrue(string(response.body().get("url")).contains("SAMLRequest="));
    }

    @Test
    void initiateSsoRejectsUnknownDomain() {
        assertError(HttpStatus.NOT_FOUND, "sso_provider_not_found", () -> client.initiateSso(new SsoRequest(uniqueDomain("unknown"), null, null, true, null, null, null)));
    }

    @Test
    void initiateSsoRejectsMissingDomainAndProvider() {
        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.initiateSso(new SsoRequest(null, null, null, true, null, null, null)));
    }

    @Test
    void samlAcsWithUnknownRelayStateRedirectsToSiteWithError() {
        HttpResponse<?> response = client.samlAcs(UUID.randomUUID().toString(), null, null);

        assertEquals(HttpStatus.SEE_OTHER, response.getStatus());
        String location = location(response);
        assertTrue(location.startsWith(Supabase.SITE_URL), location);
        assertTrue(location.contains("error_code=saml_relay_state_not_found"), location);
    }

    @Test
    void samlAcsWithoutSamlResponseRedirectsToSiteWithError() {
        HttpResponse<?> response = client.samlAcs(null, null, null);

        assertEquals(HttpStatus.SEE_OTHER, response.getStatus());
        String location = location(response);
        assertTrue(location.startsWith(Supabase.SITE_URL), location);
        assertTrue(location.contains("error="), location);
    }

    // ------------------------------------------------------------------ admin SSO providers

    @Test
    void createAdminSsoProviderRegistersSamlProvider() {
        String domain = uniqueDomain("create");
        String entityId = "https://idp." + domain;
        SAMLAttributeMappingSchema mapping = new SAMLAttributeMappingSchema(Map.of(
            "email", new SAMLAttributeMappingSchema.AttributeMapping("mail", null, null)));

        HttpResponse<SSOProviderSchema> response = client.createAdminSsoProvider(new CreateSsoProviderRequest("saml", null, Supabase.samlIdpMetadata(entityId), List.of(domain), mapping));

        assertEquals(HttpStatus.CREATED, response.getStatus());
        SSOProviderSchema provider = response.body();
        assertNotNull(provider.id());
        assertEquals(entityId, provider.saml().entityId());
        assertNull(provider.saml().metadataUrl());
        assertEquals(List.of(domain), provider.ssoDomains().stream().map(SSOProviderSchema.SsoDomain::domain).toList());
        assertEquals("mail", provider.saml().attributeMapping().keys().get("email").name());
    }

    @Test
    void createAdminSsoProviderRejectsMissingMetadata() {
        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.createAdminSsoProvider(new CreateSsoProviderRequest("saml", null, null, List.of(uniqueDomain("no-metadata")), null)));
    }

    @Test
    void listAdminSsoProvidersIncludesCreatedProvider() {
        SSOProviderSchema provider = createSsoProvider(uniqueDomain("list"));

        HttpResponse<Map<String, Object>> response = client.listAdminSsoProviders();

        assertEquals(HttpStatus.OK, response.getStatus());
        List<Map<String, Object>> items = list(response.body().get("items"));
        assertTrue(items.stream().anyMatch(item -> provider.id().equals(item.get("id"))));
    }

    @Test
    void getAdminSsoProviderReturnsProvider() {
        String domain = uniqueDomain("get");
        SSOProviderSchema created = createSsoProvider(domain);

        HttpResponse<SSOProviderSchema> response = client.getAdminSsoProvider(created.id());

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(created.id(), response.body().id());
        assertEquals(domain, response.body().ssoDomains().getFirst().domain());
        assertTrue(response.body().saml().metadataXml().contains("IDPSSODescriptor"));
    }

    @Test
    void getAdminSsoProviderRejectsUnknownProvider() {
        assertError(HttpStatus.NOT_FOUND, "sso_provider_not_found", () -> client.getAdminSsoProvider(UUID.randomUUID().toString()));
    }

    @Test
    void updateAdminSsoProviderReplacesDomains() {
        SSOProviderSchema created = createSsoProvider(uniqueDomain("update"));
        String newDomain = uniqueDomain("updated");

        HttpResponse<SSOProviderSchema> response = client.updateAdminSsoProvider(created.id(),
            new UpdateSsoProviderRequest(null, null, List.of(newDomain), null));

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(List.of(newDomain), response.body().ssoDomains().stream().map(SSOProviderSchema.SsoDomain::domain).toList());
    }

    @Test
    void updateAdminSsoProviderRejectsUnknownProvider() {
        assertError(HttpStatus.NOT_FOUND, "sso_provider_not_found", () -> client.updateAdminSsoProvider(UUID.randomUUID().toString(),
            new UpdateSsoProviderRequest(null, null, List.of(uniqueDomain("ghost")), null)));
    }

    @Test
    void deleteAdminSsoProviderRemovesProvider() {
        SSOProviderSchema created = createSsoProvider(uniqueDomain("delete"));

        HttpResponse<SSOProviderSchema> response = client.deleteAdminSsoProvider(created.id());

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(created.id(), response.body().id());
        assertError(HttpStatus.NOT_FOUND, "sso_provider_not_found", () -> client.getAdminSsoProvider(created.id()));
    }

    @Test
    void deleteAdminSsoProviderRejectsUnknownProvider() {
        assertError(HttpStatus.NOT_FOUND, "sso_provider_not_found", () -> client.deleteAdminSsoProvider(UUID.randomUUID().toString()));
    }

    // ------------------------------------------------------------------ admin OAuth clients

    @Test
    void createAdminOAuthClientReturnsConfidentialClientWithSecret() {
        HttpResponse<OAuthClientSchema> response = client.createAdminOAuthClient(confidentialClientRequest("Admin App"));

        assertEquals(HttpStatus.CREATED, response.getStatus());
        OAuthClientSchema created = response.body();
        assertNotNull(created.clientId());
        assertNotNull(created.clientSecret());
        assertEquals("Admin App", created.clientName());
        assertEquals("confidential", created.clientType());
        assertEquals("client_secret_post", created.tokenEndpointAuthMethod());
        assertEquals("manual", created.registrationType());
        assertEquals(List.of("https://app.example.com/callback"), created.redirectUris());
        assertEquals(List.of("authorization_code", "refresh_token"), created.grantTypes());
    }

    @Test
    void createAdminOAuthClientRejectsNonLoopbackHttpRedirect() {
        OAuthClientRegistrationRequest request = new OAuthClientRegistrationRequest("Bad App", null, null,
            List.of("http://app.example.com/callback"), null, null, null, null, null);

        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.createAdminOAuthClient(request));
    }

    @Test
    void listAdminOAuthClientsIncludesCreatedClient() {
        OAuthClientSchema created = client.createAdminOAuthClient(confidentialClientRequest("Listed App")).body();

        HttpResponse<Map<String, Object>> response = client.listAdminOAuthClients(1, 100);

        assertEquals(HttpStatus.OK, response.getStatus());
        List<Map<String, Object>> clients = list(response.body().get("clients"));
        assertTrue(clients.stream().anyMatch(c -> created.clientId().equals(c.get("client_id"))));
        assertTrue(clients.stream().noneMatch(c -> c.containsKey("client_secret")), "list must not leak secrets");
    }

    @Test
    void getAdminOAuthClientReturnsClientWithoutSecret() {
        OAuthClientSchema created = client.createAdminOAuthClient(confidentialClientRequest("Fetched App")).body();

        HttpResponse<OAuthClientSchema> response = client.getAdminOAuthClient(created.clientId());

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(created.clientId(), response.body().clientId());
        assertEquals("Fetched App", response.body().clientName());
        assertNull(response.body().clientSecret());
    }

    @Test
    void getAdminOAuthClientRejectsUnknownClient() {
        assertError(HttpStatus.NOT_FOUND, "oauth_client_not_found", () -> client.getAdminOAuthClient(UUID.randomUUID().toString()));
    }

    @Test
    void updateAdminOAuthClientChangesName() {
        OAuthClientSchema created = client.createAdminOAuthClient(confidentialClientRequest("Old Name")).body();

        HttpResponse<OAuthClientSchema> response = client.updateAdminOAuthClient(created.clientId(),
            new OAuthClientUpdateRequest("New Name", "https://app.example.com", null, null, null, null));

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("New Name", response.body().clientName());
        assertEquals("https://app.example.com", response.body().clientUri());
    }

    @Test
    void updateAdminOAuthClientRejectsEmptyUpdate() {
        OAuthClientSchema created = client.createAdminOAuthClient(confidentialClientRequest("Unchanged")).body();

        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.updateAdminOAuthClient(created.clientId(),
            new OAuthClientUpdateRequest(null, null, null, null, null, null)));
    }

    @Test
    void regenerateAdminOAuthClientSecretReturnsNewSecret() {
        OAuthClientSchema created = client.createAdminOAuthClient(confidentialClientRequest("Rotated App")).body();

        HttpResponse<OAuthClientSchema> response = client.regenerateAdminOAuthClientSecret(created.clientId());

        assertEquals(HttpStatus.OK, response.getStatus());
        assertNotNull(response.body().clientSecret());
        assertNotEquals(created.clientSecret(), response.body().clientSecret());
    }

    @Test
    void regenerateAdminOAuthClientSecretRejectsPublicClient() {
        OAuthClientSchema publicClient = client.registerOAuthClient(publicClientRequest("Public App")).body();

        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.regenerateAdminOAuthClientSecret(publicClient.clientId()));
    }

    @Test
    void deleteAdminOAuthClientRemovesClient() {
        OAuthClientSchema created = client.createAdminOAuthClient(confidentialClientRequest("Doomed App")).body();

        HttpResponse<?> response = client.deleteAdminOAuthClient(created.clientId());

        assertEquals(HttpStatus.NO_CONTENT, response.getStatus());
        assertError(HttpStatus.NOT_FOUND, "oauth_client_not_found", () -> client.getAdminOAuthClient(created.clientId()));
    }

    @Test
    void deleteAdminOAuthClientRejectsUnknownClient() {
        assertError(HttpStatus.NOT_FOUND, "oauth_client_not_found", () -> client.deleteAdminOAuthClient(UUID.randomUUID().toString()));
    }

    // ------------------------------------------------------------------ admin custom OAuth providers

    @Test
    void createCustomOAuthProviderRegistersOAuth2Provider() {
        String identifier = uniqueCustomIdentifier();

        HttpResponse<CustomOAuthProviderSchema> response = client.createCustomOAuthProvider(customProviderRequest(identifier, "Acme"));

        assertEquals(HttpStatus.CREATED, response.getStatus());
        CustomOAuthProviderSchema provider = response.body();
        assertNotNull(provider.id());
        assertEquals(identifier, provider.identifier());
        assertEquals("oauth2", provider.providerType());
        assertEquals("Acme", provider.name());
        assertEquals("acme-client-id", provider.clientId());
        assertEquals(List.of("openid", "email"), provider.scopes());
        assertEquals("https://" + Supabase.CUSTOM_PROVIDER_HOST + "/oauth/authorize", provider.authorizationUrl());
        assertEquals(true, provider.enabled());
    }

    @Test
    void createCustomOAuthProviderRejectsIdentifierWithoutPrefix() {
        CreateCustomOAuthProviderRequest request = customProviderRequest("acme-no-prefix", "Acme");

        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.createCustomOAuthProvider(request));
    }

    @Test
    void listCustomOAuthProvidersFiltersByType() {
        CustomOAuthProviderSchema created = client.createCustomOAuthProvider(customProviderRequest(uniqueCustomIdentifier(), "Listed")).body();

        HttpResponse<Map<String, Object>> all = client.listCustomOAuthProviders(null);
        HttpResponse<Map<String, Object>> oidcOnly = client.listCustomOAuthProviders("oidc");

        assertEquals(HttpStatus.OK, all.getStatus());
        assertTrue(list(all.body().get("providers")).stream().anyMatch(p -> created.id().equals(p.get("id"))));
        assertEquals(HttpStatus.OK, oidcOnly.getStatus());
        assertTrue(list(oidcOnly.body().get("providers")).stream().noneMatch(p -> created.id().equals(p.get("id"))));
    }

    @Test
    void listCustomOAuthProvidersRejectsUnknownType() {
        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.listCustomOAuthProviders("saml"));
    }

    @Test
    void getCustomOAuthProviderReturnsProvider() {
        String identifier = uniqueCustomIdentifier();
        CustomOAuthProviderSchema created = client.createCustomOAuthProvider(customProviderRequest(identifier, "Fetched")).body();

        HttpResponse<CustomOAuthProviderSchema> response = client.getCustomOAuthProvider(identifier);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(created.id(), response.body().id());
        assertEquals("Fetched", response.body().name());
    }

    @Test
    void getCustomOAuthProviderRejectsUnknownIdentifier() {
        assertError(HttpStatus.NOT_FOUND, "custom_provider_not_found", () -> client.getCustomOAuthProvider(uniqueCustomIdentifier()));
    }

    @Test
    void updateCustomOAuthProviderChangesNameAndDisables() {
        String identifier = uniqueCustomIdentifier();
        client.createCustomOAuthProvider(customProviderRequest(identifier, "Before"));
        UpdateCustomOAuthProviderRequest update = new UpdateCustomOAuthProviderRequest("After", null, null, null, null, null, null, null, null,
            false, null, null, null, null, null, null, null, null);

        HttpResponse<CustomOAuthProviderSchema> response = client.updateCustomOAuthProvider(identifier, update);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("After", response.body().name());
        assertEquals(false, response.body().enabled());
    }

    @Test
    void updateCustomOAuthProviderRejectsUnknownIdentifier() {
        UpdateCustomOAuthProviderRequest update = new UpdateCustomOAuthProviderRequest("Ghost", null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null);

        assertError(HttpStatus.NOT_FOUND, "custom_provider_not_found", () -> client.updateCustomOAuthProvider(uniqueCustomIdentifier(), update));
    }

    @Test
    void deleteCustomOAuthProviderRemovesProvider() {
        String identifier = uniqueCustomIdentifier();
        client.createCustomOAuthProvider(customProviderRequest(identifier, "Doomed"));

        HttpResponse<?> response = client.deleteCustomOAuthProvider(identifier);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatus());
        assertError(HttpStatus.NOT_FOUND, "custom_provider_not_found", () -> client.getCustomOAuthProvider(identifier));
    }

    @Test
    void deleteCustomOAuthProviderRejectsUnknownIdentifier() {
        assertError(HttpStatus.NOT_FOUND, "custom_provider_not_found", () -> client.deleteCustomOAuthProvider(uniqueCustomIdentifier()));
    }

    // ------------------------------------------------------------------ OAuth 2.1 authorization server

    @Test
    void registerOAuthClientDynamicallyCreatesPublicClient() {
        HttpResponse<OAuthClientSchema> response = client.registerOAuthClient(publicClientRequest("Dynamic App"));

        assertEquals(HttpStatus.CREATED, response.getStatus());
        OAuthClientSchema registered = response.body();
        assertNotNull(registered.clientId());
        assertNull(registered.clientSecret());
        assertEquals("public", registered.clientType());
        assertEquals("none", registered.tokenEndpointAuthMethod());
        assertEquals("dynamic", registered.registrationType());
        assertEquals(List.of(REDIRECT_URI), registered.redirectUris());
    }

    @Test
    void registerOAuthClientRejectsMissingRedirectUris() {
        OAuthClientRegistrationRequest request = new OAuthClientRegistrationRequest("No Redirects", null, null, List.of(), null, "none", null, null, null);

        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.registerOAuthClient(request));
    }

    @Test
    void authorizeOAuthClientRedirectsToConsentPage() {
        OAuthClientSchema app = client.registerOAuthClient(publicClientRequest("Authorize App")).body();
        Pkce pkce = Pkce.generate();

        HttpResponse<?> response = client.authorizeOAuthClient("code", app.clientId(), REDIRECT_URI, "email", "xyz", pkce.challenge(), "S256");

        assertEquals(HttpStatus.FOUND, response.getStatus());
        String location = location(response);
        assertTrue(location.startsWith(Supabase.SITE_URL + Supabase.OAUTH_AUTHORIZATION_PATH + "?authorization_id="), location);
    }

    @Test
    void authorizeOAuthClientRejectsUnknownClient() {
        assertError(HttpStatus.BAD_REQUEST, "oauth_client_not_found", () -> client.authorizeOAuthClient("code", UUID.randomUUID().toString(), REDIRECT_URI, null, null, Pkce.generate().challenge(), "S256"));
    }

    @Test
    void authorizeOAuthClientRejectsUnregisteredRedirectUri() {
        OAuthClientSchema app = client.registerOAuthClient(publicClientRequest("Strict App")).body();

        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.authorizeOAuthClient("code", app.clientId(), "https://evil.example.com/callback", null, null, Pkce.generate().challenge(), "S256"));
    }

    @Test
    void getOAuthAuthorizationDescribesPendingRequest() {
        OAuthClientSchema app = client.registerOAuthClient(publicClientRequest("Pending App")).body();
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("oauth-pending"));
        String authorizationId = startAuthorization(app, null, Pkce.generate(), "state-1");

        HttpResponse<Map<String, Object>> response = client.getOAuthAuthorization(bearer(session), authorizationId);

        assertEquals(HttpStatus.OK, response.getStatus());
        Map<String, Object> authorization = response.body();
        assertEquals(authorizationId, authorization.get("authorization_id"));
        assertEquals(REDIRECT_URI, authorization.get("redirect_uri"));
        assertEquals(app.clientId(), map(authorization.get("client")).get("id"));
        assertEquals("Pending App", map(authorization.get("client")).get("name"));
        assertEquals(session.user().email(), map(authorization.get("user")).get("email"));
    }

    @Test
    void getOAuthAuthorizationRejectsUnknownAuthorization() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("oauth-unknown-authorization"));

        assertError(HttpStatus.NOT_FOUND, "oauth_authorization_not_found", () -> client.getOAuthAuthorization(bearer(session), UUID.randomUUID().toString()));
    }

    @Test
    void consentOAuthAuthorizationApproveReturnsRedirectWithCode() {
        OAuthClientSchema app = client.registerOAuthClient(publicClientRequest("Approved App")).body();
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("oauth-approve"));
        String authorizationId = startAuthorization(app, session, Pkce.generate(), "state-approve");

        HttpResponse<Map<String, Object>> response = client.consentOAuthAuthorization(bearer(session), authorizationId, new ConsentOAuthAuthorizationRequest("approve"));

        assertEquals(HttpStatus.OK, response.getStatus());
        URI redirect = URI.create(string(response.body().get("redirect_url")));
        assertTrue(redirect.toString().startsWith(REDIRECT_URI + "?"), redirect.toString());
        assertNotNull(queryParam(redirect, "code"));
        assertEquals("state-approve", queryParam(redirect, "state"));
    }

    @Test
    void consentOAuthAuthorizationDenyReturnsRedirectWithError() {
        OAuthClientSchema app = client.registerOAuthClient(publicClientRequest("Denied App")).body();
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("oauth-deny"));
        String authorizationId = startAuthorization(app, session, Pkce.generate(), "state-deny");

        HttpResponse<Map<String, Object>> response = client.consentOAuthAuthorization(bearer(session), authorizationId, new ConsentOAuthAuthorizationRequest("deny"));

        assertEquals(HttpStatus.OK, response.getStatus());
        URI redirect = URI.create(string(response.body().get("redirect_url")));
        assertEquals("access_denied", queryParam(redirect, "error"));
        assertEquals("state-deny", queryParam(redirect, "state"));
    }

    @Test
    void consentOAuthAuthorizationRejectsUnknownAction() {
        OAuthClientSchema app = client.registerOAuthClient(publicClientRequest("Confused App")).body();
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("oauth-confused"));
        String authorizationId = startAuthorization(app, session, Pkce.generate(), null);

        assertError(HttpStatus.BAD_REQUEST, "validation_failed", () -> client.consentOAuthAuthorization(bearer(session), authorizationId, new ConsentOAuthAuthorizationRequest("maybe")));
    }

    @Test
    void oauthTokenExchangesAuthorizationCodeAndRefreshToken() {
        OAuthClientSchema app = client.registerOAuthClient(publicClientRequest("Token App")).body();
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("oauth-token"));
        Pkce pkce = Pkce.generate();
        String code = approve(app, session, pkce);

        HttpResponse<Map<String, Object>> response = client.oauthToken(new OAuthTokenRequest("authorization_code", code, REDIRECT_URI, pkce.verifier(), null, app.clientId(), null));

        assertEquals(HttpStatus.OK, response.getStatus());
        Map<String, Object> tokens = response.body();
        assertEquals("bearer", tokens.get("token_type"));
        assertNotNull(tokens.get("access_token"));
        assertNotNull(tokens.get("refresh_token"));
        assertEquals(session.user().id(), claim(string(tokens.get("access_token")), "sub"));

        HttpResponse<Map<String, Object>> refreshed = client.oauthToken(new OAuthTokenRequest("refresh_token", null, null, null, string(tokens.get("refresh_token")), app.clientId(), null));

        assertEquals(HttpStatus.OK, refreshed.getStatus());
        assertNotNull(refreshed.body().get("access_token"));
        assertNotEquals(tokens.get("refresh_token"), refreshed.body().get("refresh_token"));
    }

    @Test
    void oauthTokenWithFormMapRejectsWrongCodeVerifier() {
        OAuthClientSchema app = client.registerOAuthClient(publicClientRequest("Pkce App")).body();
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("oauth-pkce"));
        String code = approve(app, session, Pkce.generate());
        Map<String, String> form = Map.of(
            "grant_type", "authorization_code",
            "code", code,
            "redirect_uri", REDIRECT_URI,
            "code_verifier", Pkce.generate().verifier(),
            "client_id", app.clientId());

        assertOAuthError(HttpStatus.BAD_REQUEST, "invalid_grant", () -> client.oauthToken(form));
    }

    @Test
    void oauthTokenRejectsMissingClientAuthentication() {
        assertError(HttpStatus.BAD_REQUEST, "invalid_credentials", () -> client.oauthToken(new OAuthTokenRequest("authorization_code", "code", REDIRECT_URI, "verifier", null, null, null)));
    }

    @Test
    void listUserOAuthGrantsIncludesConsentedClient() {
        OAuthClientSchema app = client.registerOAuthClient(publicClientRequest("Granted App")).body();
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("oauth-grants"));
        approve(app, session, Pkce.generate());

        HttpResponse<List<Map<String, Object>>> response = client.listUserOAuthGrants(bearer(session));

        assertEquals(HttpStatus.OK, response.getStatus());
        List<Map<String, Object>> grants = response.body();
        assertEquals(1, grants.size());
        assertEquals(app.clientId(), map(grants.getFirst().get("client")).get("id"));
        assertEquals("Granted App", map(grants.getFirst().get("client")).get("name"));
    }

    @Test
    void listUserOAuthGrantsIsEmptyForNewUser() {
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("oauth-no-grants"));

        HttpResponse<List<Map<String, Object>>> response = client.listUserOAuthGrants(bearer(session));

        assertEquals(HttpStatus.OK, response.getStatus());
        assertTrue(response.body().isEmpty());
    }

    @Test
    void revokeUserOAuthGrantRemovesConsent() {
        OAuthClientSchema app = client.registerOAuthClient(publicClientRequest("Revoked App")).body();
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("oauth-revoke"));
        approve(app, session, Pkce.generate());

        HttpResponse<?> response = client.revokeUserOAuthGrant(bearer(session), app.clientId());

        assertEquals(HttpStatus.NO_CONTENT, response.getStatus());
        assertTrue(client.listUserOAuthGrants(bearer(session)).body().isEmpty());
    }

    @Test
    void revokeUserOAuthGrantRejectsClientWithoutGrant() {
        OAuthClientSchema app = client.registerOAuthClient(publicClientRequest("Stranger App")).body();
        AccessTokenResponseSchema session = signUpAndLogin(uniqueEmail("oauth-revoke-none"));

        assertError(HttpStatus.NOT_FOUND, "oauth_consent_not_found", () -> client.revokeUserOAuthGrant(bearer(session), app.clientId()));
    }

    // ------------------------------------------------------------------ helpers

    private static String uniqueEmail(String prefix) {
        return prefix + "-" + UUID.randomUUID() + "@example.com";
    }

    private static String uniqueDomain(String prefix) {
        return prefix + "-" + UUID.randomUUID() + ".example.com";
    }

    private static String uniqueCustomIdentifier() {
        return "custom:" + UUID.randomUUID().toString().replace("-", "");
    }

    private static SignupRequest signupRequest(String email) {
        return new SignupRequest(email, null, PASSWORD, null, null, null, null, null);
    }

    private static TokenRequest passwordGrant(String email, String password) {
        return new TokenRequest(null, password, email, null, null, null, null, null, null, null, null, null, null, null, null, null);
    }

    private static String bearer(AccessTokenResponseSchema session) {
        return "Bearer " + session.accessToken();
    }

    private AccessTokenResponseSchema signUpAndLogin(String email) {
        assertEquals(HttpStatus.OK, client.signup(null, signupRequest(email)).getStatus());
        AccessTokenResponseSchema session = client.token("password", passwordGrant(email, PASSWORD)).body();
        assertNotNull(session.accessToken());
        return session;
    }

    private Map<String, Object> generateMagicLink(String email) {
        return client.generateAdminLink(new GenerateAdminLinkRequest("magiclink", email, null, null, null, null)).body();
    }

    private UserSchema findAdminUserByEmail(String email) {
        List<Map<String, Object>> users = list(client.listAdminUsers(1, 1000).body().get("users"));
        return users.stream()
            .filter(user -> email.equals(user.get("email")))
            .findFirst()
            .map(user -> client.getAdminUser(string(user.get("id"))).body())
            .orElse(null);
    }

    private Map<String, Object> enrollTotp(AccessTokenResponseSchema session) {
        HttpResponse<Map<String, Object>> response = client.enrollFactor(bearer(session), new EnrollFactorRequest("totp", "Authenticator", "micronaut-security", null));
        assertEquals(HttpStatus.OK, response.getStatus());
        return response.body();
    }

    private AccessTokenResponseSchema verifyTotp(AccessTokenResponseSchema session, Map<String, Object> factor) {
        String factorId = string(factor.get("id"));
        String challengeId = string(client.challengeFactor(bearer(session), factorId, new ChallengeFactorRequest(null)).body().get("id"));
        String code = Supabase.totpCode(string(map(factor.get("totp")).get("secret")));
        HttpResponse<AccessTokenResponseSchema> response = client.verifyFactor(bearer(session), factorId, new VerifyFactorRequest(challengeId, code, null));
        assertEquals(HttpStatus.OK, response.getStatus());
        return response.body();
    }

    private SSOProviderSchema createSsoProvider(String domain) {
        HttpResponse<SSOProviderSchema> response = client.createAdminSsoProvider(new CreateSsoProviderRequest("saml", null, Supabase.samlIdpMetadata("https://idp." + domain), List.of(domain), null));
        assertEquals(HttpStatus.CREATED, response.getStatus());
        return response.body();
    }

    private static OAuthClientRegistrationRequest confidentialClientRequest(String name) {
        return new OAuthClientRegistrationRequest(name, null, null, List.of("https://app.example.com/callback"),
            "confidential", "client_secret_post", List.of("authorization_code", "refresh_token"), List.of("code"), null);
    }

    private static OAuthClientRegistrationRequest publicClientRequest(String name) {
        return new OAuthClientRegistrationRequest(name, "https://app.example.com", null, List.of(REDIRECT_URI),
            null, "none", List.of("authorization_code", "refresh_token"), List.of("code"), null);
    }

    private static CreateCustomOAuthProviderRequest customProviderRequest(String identifier, String name) {
        return new CreateCustomOAuthProviderRequest("oauth2", identifier, name, "acme-client-id", "acme-client-secret-fixture",
            null, List.of("openid", "email"), true, null, null, null, true, null, null, null, null,
            "https://" + Supabase.CUSTOM_PROVIDER_HOST + "/oauth/authorize", "https://" + Supabase.CUSTOM_PROVIDER_HOST + "/oauth/token",
            "https://" + Supabase.CUSTOM_PROVIDER_HOST + "/userinfo", null);
    }

    /**
     * Starts an authorization request. GoTrue binds the request to the user who first loads it through
     * {@code GET /oauth/authorizations/{id}}, which the consent page does before the user approves or denies.
     * When {@code session} is {@code null} the authorization is left unbound.
     */
    private String startAuthorization(OAuthClientSchema app, AccessTokenResponseSchema session, Pkce pkce, String state) {
        HttpResponse<?> response = client.authorizeOAuthClient("code", app.clientId(), REDIRECT_URI, "email", state, pkce.challenge(), "S256");
        assertEquals(HttpStatus.FOUND, response.getStatus());
        String authorizationId = queryParam(URI.create(location(response)), "authorization_id");
        assertNotNull(authorizationId);
        if (session != null) {
            assertEquals(HttpStatus.OK, client.getOAuthAuthorization(bearer(session), authorizationId).getStatus());
        }
        return authorizationId;
    }

    private String approve(OAuthClientSchema app, AccessTokenResponseSchema session, Pkce pkce) {
        String authorizationId = startAuthorization(app, session, pkce, null);
        Map<String, Object> consent = client.consentOAuthAuthorization(bearer(session), authorizationId, new ConsentOAuthAuthorizationRequest("approve")).body();
        String code = queryParam(URI.create(string(consent.get("redirect_url"))), "code");
        assertNotNull(code);
        return code;
    }

    private static String location(HttpResponse<?> response) {
        String location = response.getHeaders().get(HttpHeaders.LOCATION);
        assertNotNull(location, "Location header expected");
        return location;
    }

    private static String queryParam(URI uri, String name) {
        String query = uri.getRawQuery();
        if (query == null) {
            return null;
        }
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            String key = eq < 0 ? pair : pair.substring(0, eq);
            if (key.equals(name)) {
                return eq < 0 ? "" : java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static String claim(String jwt, String name) {
        String payload = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
        int index = payload.indexOf("\"" + name + "\":\"");
        assertTrue(index >= 0, "claim " + name + " missing in " + payload);
        int start = index + name.length() + 4;
        return payload.substring(start, payload.indexOf('"', start));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        assertInstanceOf(Map.class, value);
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> list(Object value) {
        assertInstanceOf(List.class, value);
        return (List<Map<String, Object>>) value;
    }

    private static String string(Object value) {
        assertNotNull(value);
        return value.toString();
    }

    /**
     * Asserts that GoTrue rejected the call with {@code status} and the given {@code error_code}.
     * The declarative client throws for error statuses except {@code 404}, which it returns as a response
     * when the method returns {@link HttpResponse}, so both shapes are accepted.
     */
    private static void assertError(HttpStatus status, String errorCode, Supplier<HttpResponse<?>> call) {
        HttpResponse<?> response = errorResponse(call);
        Map<String, Object> error = response.getBody(MAP_ARGUMENT).orElse(Map.of());
        assertEquals(status, response.getStatus(), () -> "unexpected status, body: " + error);
        assertEquals(errorCode, error.get("error_code"), () -> "unexpected error_code, body: " + error);
    }

    /** OAuth 2.1 token endpoint errors use RFC 6749 {@code error} instead of GoTrue's {@code error_code}. */
    private static void assertOAuthError(HttpStatus status, String error, Supplier<HttpResponse<?>> call) {
        HttpResponse<?> response = errorResponse(call);
        Map<String, Object> body = response.getBody(MAP_ARGUMENT).orElse(Map.of());
        assertEquals(status, response.getStatus(), () -> "unexpected status, body: " + body);
        assertEquals(error, body.get("error"), () -> "unexpected error, body: " + body);
    }

    private static void assertClientError(Supplier<HttpResponse<?>> call) {
        HttpResponse<?> response = errorResponse(call);
        assertTrue(response.getStatus().getCode() >= 400 && response.getStatus().getCode() < 500, response.getStatus().toString());
    }

    private static HttpResponse<?> errorResponse(Supplier<HttpResponse<?>> call) {
        try {
            HttpResponse<?> response = call.get();
            assertTrue(response.getStatus().getCode() >= 400, () -> "expected an error response but got " + response.getStatus());
            return response;
        } catch (HttpClientResponseException e) {
            return e.getResponse();
        }
    }

    private record Pkce(String verifier, String challenge) {
        static Pkce generate() {
            byte[] bytes = new byte[32];
            RANDOM.nextBytes(bytes);
            String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
                return new Pkce(verifier, Base64.getUrlEncoder().withoutPadding().encodeToString(digest));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
