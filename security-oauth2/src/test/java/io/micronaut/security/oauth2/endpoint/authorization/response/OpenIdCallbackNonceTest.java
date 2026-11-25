/*
 * Copyright 2026 original authors
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
package io.micronaut.security.oauth2.endpoint.authorization.response;

import io.micronaut.security.oauth2.endpoint.authorization.response.OpenIdCallbackFlow.AuthorizationRedirect;
import io.micronaut.security.oauth2.endpoint.authorization.response.OpenIdCallbackFlow.CallbackOutcome;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The nonce sent in the authorization request must still be available at the callback. If it is not, the login is
 * refused, whether or not the ID token carries a nonce claim.
 */
@ResourceLock(OpenIdCallbackFlow.NONCE_CLAIM_VALIDATOR_LOG)
class OpenIdCallbackNonceTest {
    private static final String NONCE_COOKIE = "OPENID_NONCE";

    private static OpenIdCallbackFlow flow;

    @BeforeAll
    static void start() {
        flow = OpenIdCallbackFlow.start(Map.of());
    }

    @AfterAll
    static void stop() {
        flow.close();
    }

    @Test
    void userIsAuthenticatedWhenThePersistedNonceMatchesTheNonceClaim() {
        AuthorizationRedirect redirect = flow.login();
        assertTrue(redirect.hasCookie(NONCE_COOKIE));
        flow.tokenEndpointReturnsIdTokenWithNonce(redirect.nonce());

        CallbackOutcome outcome = flow.callback(redirect, redirect.cookies());

        assertTrue(outcome.authenticated());
        assertFalse(outcome.persistedNonceMissing());
    }

    @Test
    void userIsNotAuthenticatedWhenTheNonceCookieDoesNotMatchTheNonceClaim() {
        AuthorizationRedirect redirect = flow.login();
        flow.tokenEndpointReturnsIdTokenWithNonce("a-different-nonce");

        CallbackOutcome outcome = flow.callback(redirect, redirect.cookies());

        assertFalse(outcome.authenticated());
        assertFalse(outcome.persistedNonceMissing(), "the nonce was persisted; the nonce claim did not match it");
    }

    @Test
    void userIsNotAuthenticatedWhenTheNonceCookieIsMissingAndTheIdTokenHasNoNonceClaim() {
        AuthorizationRedirect redirect = flow.login();
        flow.tokenEndpointReturnsIdTokenWithNonce(null);

        CallbackOutcome outcome = flow.callback(redirect, redirect.cookiesWithout(NONCE_COOKIE));

        assertFalse(outcome.authenticated());
        assertTrue(outcome.persistedNonceMissing(), "the login should be refused because no persisted nonce could be retrieved");
    }

    @Test
    void userIsNotAuthenticatedWhenTheNonceCookieIsMissingAndTheIdTokenHasTheNonceClaim() {
        AuthorizationRedirect redirect = flow.login();
        flow.tokenEndpointReturnsIdTokenWithNonce(redirect.nonce());

        CallbackOutcome outcome = flow.callback(redirect, redirect.cookiesWithout(NONCE_COOKIE));

        assertFalse(outcome.authenticated());
        assertTrue(outcome.persistedNonceMissing(), "the login should be refused because no persisted nonce could be retrieved");
    }
}
