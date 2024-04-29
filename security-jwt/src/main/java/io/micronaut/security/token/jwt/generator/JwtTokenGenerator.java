/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.token.jwt.generator;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.claims.ClaimsGenerator;
import io.micronaut.security.token.generator.TokenGenerator;
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.generator.claims.JwtClaimsSetAdapter;
import io.micronaut.security.token.jwt.signature.SignatureGeneratorConfiguration;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import java.text.ParseException;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JWT Token Generation.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Singleton
public class JwtTokenGenerator implements TokenGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(JwtTokenGenerator.class);

    protected final ClaimsGenerator claimsGenerator;
    protected final SignatureGeneratorConfiguration<SignedJWT, JWSAlgorithm> signatureConfiguration;
    protected final EncryptionConfiguration encryptionConfiguration;

    /**
     * @param signatureConfiguration JWT Generator signature configuration
     * @param encryptionConfiguration JWT Generator encryption configuration
     * @param claimsGenerator Claims generator
     */
    public JwtTokenGenerator(@Nullable @Named("generator") SignatureGeneratorConfiguration<SignedJWT, JWSAlgorithm> signatureConfiguration,
                             @Nullable @Named("generator") EncryptionConfiguration encryptionConfiguration,
                             ClaimsGenerator claimsGenerator) {

        this.signatureConfiguration = signatureConfiguration;
        this.encryptionConfiguration = encryptionConfiguration;
        this.claimsGenerator = claimsGenerator;
    }

    /**
     * signatureConfiguration getter.
     * @return Instance of {@link SignatureGeneratorConfiguration}
     */
    public SignatureGeneratorConfiguration getSignatureConfiguration() {
        return this.signatureConfiguration;
    }

    /**
     * encryptionConfiguration getter.
     * @return Instance of {@link EncryptionConfiguration}
     */
    public EncryptionConfiguration getEncryptionConfiguration() {
        return this.encryptionConfiguration;
    }

    /**
     * Generate a JWT from a claims set.
     * @throws JOSEException thrown in the JWT generation
     * @throws ParseException thrown in the JWT generation
     * @param claimsSet the claims set
     * @return the JWT
     */
    protected String internalGenerate(final JWTClaimsSet claimsSet) throws Exception {
        JWT jwt;
        // signature?
        if (signatureConfiguration == null) {
            jwt = new PlainJWT(claimsSet);
        } else {
            jwt = signatureConfiguration.sign(new JwtClaimsSetAdapter(claimsSet));
        }

        // encryption?
        if (encryptionConfiguration != null) {
            return encryptionConfiguration.encrypt(jwt);
        } else {
            return jwt.serialize();
        }
    }

    /**
     * Generate a JWT from a map of claims.
     * @throws JOSEException thrown in the JWT generation
     * @throws ParseException thrown in the JWT generation
     * @param claims the map of claims
     * @return the created JWT
     */
    protected String generate(final Map<String, Object> claims) throws Exception {
        // claims builder
        final JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

        // add claims
        for (final Map.Entry<String, Object> entry : claims.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }

        return internalGenerate(builder.build());
    }

    /**
     *
     * @param authentication Authenticated user's representation.
     * @param expiration The amount of time in seconds until the token expires
     * @return JWT token
     */
    @Override
    public Optional<String> generateToken(Authentication authentication, @Nullable Integer expiration) {
        Map<String, Object> claims = claimsGenerator.generateClaims(authentication, expiration);
        return generateToken(claims);
    }

    /**
     *
     * @param claims JWT claims
     * @return JWT token
     */
    @Override
    public Optional<String> generateToken(Map<String, Object> claims) {
        try {
            return Optional.of(generate(claims));
        } catch (Exception e) {
            if (LOG.isWarnEnabled() && e instanceof ParseException) {
                LOG.warn("Parse exception while generating token {}", e.getMessage());
            }
            if (LOG.isWarnEnabled() && e instanceof JOSEException) {
                LOG.warn("JOSEException while generating token {}", e.getMessage());
            }
        }
        return Optional.empty();
    }
}
