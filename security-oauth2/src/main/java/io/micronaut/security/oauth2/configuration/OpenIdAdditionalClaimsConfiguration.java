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
package io.micronaut.security.oauth2.configuration;

/**
 * Configuration for additional claims to be added to the
 * resulting JWT created from an OpenID authentication.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public interface OpenIdAdditionalClaimsConfiguration {

    /**
     * @return True if the provider's JWT should be included in the Micronaut JWT
     */
    boolean isJwt();

    /**
     * @return True if the provider's access token should be included in the Micronaut JWT
     */
    boolean isAccessToken();

    /**
     * @return True if the provider's refresh token should be included in the Micronaut JWT
     */
    boolean isRefreshToken();
}
