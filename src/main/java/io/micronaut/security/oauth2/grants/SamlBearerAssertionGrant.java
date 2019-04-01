/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.grants;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.Introspected;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * SAML 2.0 bearer assertion grant.
 * @see <a href="https://tools.ietf.org/html/rfc7522#section-2.1"> Using SAML Assertions as Authorization Grants</a>
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Introspected
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class SamlBearerAssertionGrant {

    private String grantType = GrantType.SAML_2_0_BEARER_ASSERTION_GRANT.getGrantType();
    private String assertion;
    private String scope;

    /**
     * Instantiates a SamlBearerAssertionGrant.
     */
    public SamlBearerAssertionGrant() {

    }

    /**
     *
     * @return urn:ietf:params:oauth:grant-type:saml2-bearer
     */
    @Nonnull
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
     * @return The SAML 2.0 assertion, base 64 URL encoded.
     */
    @Nonnull
    public String getAssertion() {
        return assertion;
    }

    /**
     *
     * @param assertion The SAML 2.0 assertion, base 64 URL encoded.
     */
    public void setAssertion(@Nonnull String assertion) {
        this.assertion = assertion;
    }
}
