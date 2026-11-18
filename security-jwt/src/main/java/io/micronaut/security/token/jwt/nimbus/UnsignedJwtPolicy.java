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
package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.token.jwt.config.JwtConfiguration;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Decides whether an unsigned JWT (JWS header {@code alg=none}) is accepted.
 * Unsigned JWTs are only accepted when there is no signature configuration and
 * {@link JwtConfiguration#isAcceptUnsignedTokens()} is explicitly {@code true}.
 * If any signature configuration is present, an unsigned JWT is always rejected.
 * Being a singleton shared by the JWT validators, each warning is logged once per application context.
 * @since 5.6.0
 */
@Internal
@Singleton
final class UnsignedJwtPolicy {
    private static final Logger LOG = LoggerFactory.getLogger(UnsignedJwtPolicy.class);
    private static final String ACCEPT_UNSIGNED_TOKENS_PROPERTY = JwtConfigurationProperties.PREFIX + ".accept-unsigned-tokens";

    private final boolean noSignatures;
    private final boolean accepted;
    private final AtomicBoolean rejectionWarned = new AtomicBoolean();

    UnsignedJwtPolicy(List<SignatureConfiguration> imperativeSignatureConfigurations,
                      List<ReactiveSignatureConfiguration<SignedJWT>> reactiveSignatureConfigurations,
                      JwtConfiguration jwtConfiguration) {
        this.noSignatures = imperativeSignatureConfigurations.isEmpty() && reactiveSignatureConfigurations.isEmpty();
        this.accepted = noSignatures && jwtConfiguration.isAcceptUnsignedTokens();
        if (accepted) {
            LOG.warn("{} is true and no signature configuration is present: unsigned JWTs (alg=none) are accepted. "
                    + "Unsigned tokens can be forged by anyone. Do not enable this in production.", ACCEPT_UNSIGNED_TOKENS_PROPERTY);
        }
    }

    /**
     * @return Whether an unsigned JWT should be accepted
     */
    boolean acceptsUnsignedJwt() {
        if (accepted) {
            LOG.debug("JWT is not signed, no signature configurations and {} is true -> verified", ACCEPT_UNSIGNED_TOKENS_PROPERTY);
            return true;
        }
        if (!noSignatures) {
            LOG.debug("A non-signed JWT cannot be accepted as signature configurations have been defined");
        } else if (rejectionWarned.compareAndSet(false, true)) {
            LOG.warn("Rejected an unsigned JWT (alg=none) because no signature configuration is present. "
                    + "Configure a signature (e.g. micronaut.security.token.jwt.signatures.secret.generator.secret) "
                    + "or set {} to true to accept unsigned tokens (not recommended). This warning is logged once.", ACCEPT_UNSIGNED_TOKENS_PROPERTY);
        } else {
            LOG.debug("Rejected an unsigned JWT because no signature configuration is present and {} is false", ACCEPT_UNSIGNED_TOKENS_PROPERTY);
        }
        return false;
    }
}
