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

package io.micronaut.security.oauth2.endpoint.authorization.request;

/**
 * OpenID Connect scope values.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public enum OpenIdScope {

    OPENID("openid"),

    /**
     * This scope value requests access to the End-User's default profile Claims, which are: name, family_name, given_name, middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, and updated_at.
     */
    PROFILE("profile"),

    /**
     * This scope value requests access to the End-User's default profile Claims, which are: name, family_name, given_name, middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, and updated_at.
     */
    EMAIL("email"),

    /**
     * This scope value requests access to the address Claim.
     */
    ADDRESS("address"),

    /**
     * This scope value requests access to the phone_number and phone_number_verified Claims.
     */
    PHONE("phone");

    private String scope;

    /**
     * OpenID scope constructor.
     * @param scope a string representation of the scope.
     */
    OpenIdScope(String scope) {
        this.scope = scope;
    }

    /**
     *
     * @return a string representation of the scope.
     */
    @Override
    public String toString() {
        return this.scope;
    }
}
