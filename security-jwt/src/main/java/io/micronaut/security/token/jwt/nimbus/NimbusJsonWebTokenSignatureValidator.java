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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NonNull;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.jwt.validator.JsonWebTokenSignatureValidator;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Validates the signature of a JSON Web Token using Nimbus JOSE + JWT.
 * @author Sergio del Amo
 * @since 4.8.0
 */
@Internal
@Singleton
class NimbusJsonWebTokenSignatureValidator implements JsonWebTokenSignatureValidator<SignedJWT> {
    private static final Logger LOG = LoggerFactory.getLogger(NimbusJsonWebTokenSignatureValidator.class);
    private final List<SignatureConfiguration> signatures;

    public NimbusJsonWebTokenSignatureValidator(List<SignatureConfiguration> signatures) {
        this.signatures = signatures;
    }

    @Override
    public boolean validateSignature(@NonNull SignedJWT signedToken) {
        // The algorithm comes from the untrusted token header. It must never be used as a key of any
        // unbounded structure (e.g. a cache), because a client could send a distinct value per request
        // and exhaust memory. The configuration list is small, so we partition it on every call instead.
        JWSAlgorithm algorithm = signedToken.getHeader().getAlgorithm();
        List<SignatureConfiguration> supporting = new ArrayList<>(signatures.size());
        List<SignatureConfiguration> notSupporting = new ArrayList<>(signatures.size());
        for (SignatureConfiguration signature : signatures) {
            if (signature.supports(algorithm)) {
                supporting.add(signature);
            } else {
                notSupporting.add(signature);
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signature configurations supporting algorithm {} : {}", algorithm, supporting);
        }
        return validate(signedToken, supporting) || validate(signedToken, notSupporting);
    }

    private static boolean validate(SignedJWT jwt, SignatureConfiguration signatureConfiguration) {
        try {
            boolean verified = signatureConfiguration.verify(jwt);
            if (verified) {
                return true;
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Signature verification failed for {} with signature configuration: {}", JwtLogUtils.describe(jwt), signatureConfiguration);
            }
        } catch (final JOSEException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Verification failed with signature configuration: {}, passing to the next one", signatureConfiguration);
            }
        }
        return false;
    }

    private static boolean validate(SignedJWT jwt, List<SignatureConfiguration> signatureConfigurations) {
        for (SignatureConfiguration config: signatureConfigurations) {
            if (validate(jwt, config)) {
                return true;
            }
        }
        return false;
    }
}
