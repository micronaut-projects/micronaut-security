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
package io.micronaut.security.token.jwt.validator.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Internal
public class SignedJwtJsonWebTokenSignatureValidator implements JsonWebTokenSignatureValidator<SignedJWT> {

    private final List<SignatureConfiguration> signatures;

    private final ConcurrentHashMap<JWSAlgorithm, List<SignatureConfiguration>> sortedSignaturesMap = new ConcurrentHashMap<>();
    private static final Logger LOG = LoggerFactory.getLogger(SignedJwtJsonWebTokenSignatureValidator.class);

    public SignedJwtJsonWebTokenSignatureValidator(List<SignatureConfiguration> signatures) {
        this.signatures = signatures;
    }

    @Override
    public boolean validateSignature(SignedJWT signedToken) {
        List<SignatureConfiguration> sortedSignatures = sortedSignaturesMap.computeIfAbsent(signedToken.getHeader().getAlgorithm(), alg -> {
            List<SignatureConfiguration> sortedConfigs = new ArrayList<>(signatures);
            sortedConfigs.sort(comparator(alg));
            if (LOG.isDebugEnabled()) {
                LOG.debug("Sorted signature configurations for algorithm {} : {}", alg, sortedConfigs);
            }
            return sortedConfigs;
        });
        return validate(signedToken, sortedSignatures).isPresent();
    }

    private static Optional<JWT> validate(SignedJWT jwt, SignatureConfiguration signatureConfiguration) {
        try {
            boolean verified = signatureConfiguration.verify(jwt);
            if (!verified) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("JWT Signature verification failed: {}", jwt.getParsedString());
                }
            } else {
                return Optional.of(jwt);
            }
        } catch (final JOSEException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Verification failed with signature configuration: {}, passing to the next one", signatureConfiguration);
            }
        }
        return Optional.empty();
    }

    private static Optional<JWT> validate(SignedJWT jwt, List<SignatureConfiguration> signatureConfigurations) {
        for (SignatureConfiguration config: signatureConfigurations) {
            Optional<JWT> optionalJWT = validate(jwt, config);
            if (optionalJWT.isPresent()) {
                return optionalJWT;
            }
        }
        return Optional.empty();
    }


    private static Comparator<SignatureConfiguration> comparator(JWSAlgorithm algorithm) {
        return (sig, otherSig) -> {
            boolean supports = sig.supports(algorithm);
            boolean otherSupports = otherSig.supports(algorithm);
            if (supports == otherSupports) {
                return 0;
            } else if (supports) {
                return -1;
            } else {
                return 1;
            }
        };
    }

    private record SortKey(JWSAlgorithm algorithm, @Nullable String kid) {
        public SortKey(SignedJWT jwt) {
            this(jwt.getHeader().getAlgorithm(), jwt.getHeader().getKeyID());
            }
    }
}