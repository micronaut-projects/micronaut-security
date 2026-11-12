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
package io.micronaut.security.token.biscuit;

import io.micronaut.http.HttpRequest;
import org.biscuitsec.biscuit.token.Authorizer;
import org.biscuitsec.biscuit.token.Biscuit;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * Context available when mapping an authorized Biscuit token to an authentication.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
@SuppressWarnings("java:S6206") // Keep JavaBean accessors for Micronaut public API consistency.
public final class BiscuitAuthenticationContext {

    private final Biscuit token;
    private final Authorizer authorizer;
    private final long policyIndex;
    private final List<String> revocationIdentifiers;
    @Nullable
    private final HttpRequest<?> request;

    /**
     * @param token The verified Biscuit token
     * @param authorizer The authorizer after successful authorization
     * @param policyIndex The matched allow policy index
     * @param revocationIdentifiers The token revocation identifiers
     * @param request The HTTP request
     */
    public BiscuitAuthenticationContext(Biscuit token,
                                        Authorizer authorizer,
                                        long policyIndex,
                                        List<String> revocationIdentifiers,
                                        @Nullable HttpRequest<?> request) {
        this.token = token;
        this.authorizer = authorizer;
        this.policyIndex = policyIndex;
        this.revocationIdentifiers = List.copyOf(revocationIdentifiers);
        this.request = request;
    }

    /**
     * @return The verified Biscuit token
     */
    public Biscuit getToken() {
        return token;
    }

    /**
     * @return The authorizer after successful authorization
     */
    public Authorizer getAuthorizer() {
        return authorizer;
    }

    /**
     * @return The matched allow policy index
     */
    public long getPolicyIndex() {
        return policyIndex;
    }

    /**
     * @return The token revocation identifiers
     */
    public List<String> getRevocationIdentifiers() {
        return revocationIdentifiers;
    }

    /**
     * @return The HTTP request
     */
    @Nullable
    @SuppressWarnings("java:S1452") // The request body type is intentionally unknown to authentication mappers.
    public HttpRequest<?> getRequest() {
        return request;
    }
}
