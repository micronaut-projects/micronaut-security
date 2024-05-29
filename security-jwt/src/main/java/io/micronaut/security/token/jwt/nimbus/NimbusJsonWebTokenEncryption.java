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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.validator.JsonWebTokenEncryption;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * {@link JsonWebTokenEncryption} implementation using Nimbus JOSE + JWT.
 * @author Sergio del Amo
 * @since 4.8.0
 */
@Singleton
@Internal
class NimbusJsonWebTokenEncryption implements JsonWebTokenEncryption<EncryptedJWT, SignedJWT> {
    private static final Logger LOG = LoggerFactory.getLogger(NimbusJsonWebTokenEncryption.class);
    private final List<EncryptionConfiguration> encryptionConfigurationList;

    NimbusJsonWebTokenEncryption(List<EncryptionConfiguration> encryptionConfigurationList) {
        this.encryptionConfigurationList = encryptionConfigurationList;
    }

    @Override
    @NonNull
    public Optional<SignedJWT> decrypt(@NonNull EncryptedJWT jwt) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Validating encrypted JWT");
        }
        if (LOG.isDebugEnabled() && encryptionConfigurationList.isEmpty()) {
            LOG.debug("JWT is encrypted and no encryption configurations -> not verified");
            return Optional.empty();
        }
        final JWEHeader header = jwt.getHeader();
        List<EncryptionConfiguration> sortedConfigs = new ArrayList<>(encryptionConfigurationList);
        sortedConfigs.sort(comparator(header));
        for (EncryptionConfiguration config: sortedConfigs) {
            Optional<SignedJWT> signedJWT = decrypt(jwt, config);
            if (signedJWT.isPresent()) {
                return signedJWT;
            }
        }
        return Optional.empty();
    }

    @NonNull
    private Optional<SignedJWT> decrypt(@NonNull EncryptedJWT jwt, @NonNull EncryptionConfiguration config) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Using encryption configuration: {}", config);
        }
        try {
            config.decrypt(jwt);
            SignedJWT signedJWT = jwt.getPayload().toSignedJWT();
            if (signedJWT == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Encrypted JWT couldn't be converted to a signed JWT.");
                }
                return Optional.empty();
            }
            return Optional.of(signedJWT);
        } catch (final JOSEException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Decryption fails with encryption configuration: {}, passing to the next one", config);
            }
            return Optional.empty();
        }
    }

    private static Comparator<EncryptionConfiguration> comparator(JWEHeader header) {
        final JWEAlgorithm algorithm = header.getAlgorithm();
        final EncryptionMethod method = header.getEncryptionMethod();
        return (sig, otherSig) -> {
            boolean supports = sig.supports(algorithm, method);
            boolean otherSupports = otherSig.supports(algorithm, method);
            if (supports == otherSupports) {
                return 0;
            } else if (supports) {
                return -1;
            } else {
                return 1;
            }
        };
    }
}
