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
 * With the nonce persisted in the session, the nonce is removed from the session when the callback reads it. A
 * callback without the session, or a second callback for the same authorization request, finds no nonce and the
 * login is refused.
 */
@ResourceLock(OpenIdCallbackFlow.NONCE_CLAIM_VALIDATOR_LOG)
class OpenIdCallbackSessionNonceTest {
    private static final String SESSION_COOKIE = "SESSION";

    private static OpenIdCallbackFlow flow;

    @BeforeAll
    static void start() {
        flow = OpenIdCallbackFlow.start(Map.of(
            "micronaut.security.session.enabled", true,
            "micronaut.security.oauth2.openid.nonce.persistence", "session"));
    }

    @AfterAll
    static void stop() {
        flow.close();
    }

    @Test
    void userIsAuthenticatedWhenTheNonceInTheSessionMatchesTheNonceClaim() {
        AuthorizationRedirect redirect = flow.login();
        assertTrue(redirect.hasCookie(SESSION_COOKIE));
        assertFalse(redirect.hasCookie("OPENID_NONCE"));
        flow.tokenEndpointReturnsIdTokenWithNonce(redirect.nonce());

        assertTrue(flow.isAuthenticatedAfterCallback(redirect, redirect.cookies()));
    }

    @Test
    void userIsNotAuthenticatedWhenTheSessionIsMissingAndTheIdTokenHasNoNonceClaim() {
        AuthorizationRedirect redirect = flow.login();
        flow.tokenEndpointReturnsIdTokenWithNonce(null);

        CallbackOutcome outcome = flow.callback(redirect, redirect.cookiesWithout(SESSION_COOKIE));

        assertFalse(outcome.authenticated());
        assertTrue(outcome.persistedNonceMissing(), "the login should be refused because no persisted nonce could be retrieved");
    }

    @Test
    void secondCallbackForTheSameAuthorizationRequestIsRefusedBecauseTheNonceIsNoLongerInTheSession() {
        AuthorizationRedirect redirect = flow.login();
        flow.tokenEndpointReturnsIdTokenWithNonce(redirect.nonce());
        assertTrue(flow.isAuthenticatedAfterCallback(redirect, redirect.cookies()));

        CallbackOutcome outcome = flow.callback(redirect, redirect.cookies());

        assertFalse(outcome.authenticated());
        assertTrue(outcome.persistedNonceMissing(), "the login should be refused because no persisted nonce could be retrieved");
    }

    @Test
    void secondCallbackIsRefusedEvenIfTheIdTokenHasNoNonceClaim() {
        AuthorizationRedirect redirect = flow.login();
        flow.tokenEndpointReturnsIdTokenWithNonce(redirect.nonce());
        assertTrue(flow.isAuthenticatedAfterCallback(redirect, redirect.cookies()));
        flow.tokenEndpointReturnsIdTokenWithNonce(null);

        CallbackOutcome outcome = flow.callback(redirect, redirect.cookies());

        assertFalse(outcome.authenticated());
        assertTrue(outcome.persistedNonceMissing(), "the login should be refused because no persisted nonce could be retrieved");
    }
}
