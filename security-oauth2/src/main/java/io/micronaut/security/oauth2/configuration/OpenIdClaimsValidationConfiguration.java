/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.oauth2.configuration;

/**
 * Configuration to determine if a claim validation is enabled
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public interface OpenIdClaimsValidationConfiguration {

    /**
     * @return Whether {@link io.micronaut.security.oauth2.endpoint.token.response.validation.IssuerClaimValidator} is enabled.
     */
    boolean isIssuer();

    /**
     * @return Whether {@link io.micronaut.security.oauth2.endpoint.token.response.validation.AudienceClaimValidator} is enabled.
     */
    boolean isAudience();

    /**
     * @return Whether {@link io.micronaut.security.oauth2.endpoint.token.response.validation.AuthorizedPartyClaimValidator} is enabled.
     */
    boolean isAuthorizedParty();
}
