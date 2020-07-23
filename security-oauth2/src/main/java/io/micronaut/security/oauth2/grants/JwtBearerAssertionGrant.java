/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.oauth2.grants;

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.Introspected;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * JWT bearer assertion grant.
 * @see <a href="https://tools.ietf.org/html/rfc7523#section-2.1">Using JWTs as Authorization Grants</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Introspected
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class JwtBearerAssertionGrant {

    private String grantType = GrantType.JWT_BEARER_ASSERTION_GRANT.toString();
    private String assertion;
    private String scope;

    /**
     * Default Constructor.
     */
    public JwtBearerAssertionGrant() {

    }

    /**
     *
     * @return urn:ietf:params:oauth:grant-type:saml2-bearer.
     */
    @NonNull
    public String getGrantType() {
        return grantType;
    }

    /**
     *
     * @return Requested scope values for the access token.
     */
    @Nullable
    public String getScope() {
        return scope;
    }

    /**
     *
     * @param scope Requested scope values for the access token.
     */
    public void setScope(@Nullable String scope) {
        this.scope = scope;
    }

    /**
     *
     * @return The JWT assertion.
     */
    @NonNull
    public String getAssertion() {
        return assertion;
    }

    /**
     *
     * @param assertion The JWT assertion.
     */
    public void setAssertion(@NonNull String assertion) {
        this.assertion = assertion;
    }
}
