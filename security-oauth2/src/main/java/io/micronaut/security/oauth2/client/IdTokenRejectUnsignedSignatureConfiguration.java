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
package io.micronaut.security.oauth2.client;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import jakarta.inject.Singleton;

/**
 * Keeps ID token authentication fail-closed.
 *
 * <p>The JSON Web Token validators accept unsigned JWTs when no {@link SignatureConfiguration} bean exists.
 * With {@code micronaut.security.authentication: idtoken}, signature configurations are derived from the JWKS of
 * each enabled OpenID provider, so disabling every OAuth 2.0 client, or configuring none, would otherwise leave
 * no signature configuration and unsigned tokens would authenticate requests. This configuration supports no
 * algorithm and verifies no token. Its presence makes the validators reject unsigned JWTs while the JWKS of the
 * enabled providers keep verifying signed ones.</p>
 *
 * @author Sergio del Amo
 * @since 4.18.2
 */
@Internal
@Singleton
@Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "idtoken")
final class IdTokenRejectUnsignedSignatureConfiguration implements SignatureConfiguration {

    @Override
    public String supportedAlgorithmsMessage() {
        return "No algorithm is supported. ID token authentication rejects unsigned JWTs";
    }

    @Override
    public boolean supports(JWSAlgorithm algorithm) {
        return false;
    }

    @Override
    public boolean verify(SignedJWT jwt) {
        return false;
    }

    @Override
    public String toString() {
        return IdTokenRejectUnsignedSignatureConfiguration.class.getSimpleName();
    }
}
