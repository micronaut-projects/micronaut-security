/*
 * Copyright 2017-2024 original authors
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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * Adapts from {@link SignatureConfiguration} to {@link ReactiveSignatureConfiguration}.
 * @author Sergio del Amo
 * @since 4.8.0
 */
public class NimbusReactiveSignatureConfigurationAdapter implements ReactiveSignatureConfiguration<SignedJWT> {
    private static final Logger LOG = LoggerFactory.getLogger(NimbusReactiveSignatureConfigurationAdapter.class);

    private final SignatureConfiguration signatureConfiguration;

    public NimbusReactiveSignatureConfigurationAdapter(SignatureConfiguration signatureConfiguration) {
        this.signatureConfiguration = signatureConfiguration;
    }

    @Override
    @SingleResult
    @NonNull
    public Publisher<Boolean> verify(@NonNull SignedJWT jwt) {
        try {
            boolean result = signatureConfiguration.verify(jwt);
            if (LOG.isDebugEnabled()) {
                if (result) {
                    LOG.debug("JWT signature verified");
                } else {
                    LOG.debug("JWT signature not verified");
                }
            }
            return Mono.just(result);
        } catch (JOSEException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error verifying JWT signature", e);
            }
            return Mono.just(false);
        }
    }
}
