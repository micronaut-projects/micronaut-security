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

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.token.jwt.validator.JsonWebTokenEncryption;
import io.micronaut.security.token.jwt.validator.JsonWebTokenParser;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.text.ParseException;
import java.util.Optional;

/**
 * {@link JsonWebTokenParser} implementation using Nimbus JOSE + JWT.
 * @author Sergio del Amo
 * @since 4.8.0
 */
@Singleton
class NimbusJsonWebTokenParser implements JsonWebTokenParser<JWT> {
    private static final String DOT = ".";
    private static final Logger LOG = LoggerFactory.getLogger(NimbusJsonWebTokenParser.class);
    private final JsonWebTokenEncryption<EncryptedJWT, SignedJWT> jsonWebTokenEncryption;

    NimbusJsonWebTokenParser(JsonWebTokenEncryption<EncryptedJWT, SignedJWT> jsonWebTokenEncryption) {
        this.jsonWebTokenEncryption = jsonWebTokenEncryption;
    }

    @Override
    @NonNull
    public Optional<JWT> parse(@NonNull String token) {
        try {
            if (hasAtLeastTwoDots(token)) {
                JWT jwt = JWTParser.parse(token);
                if (jwt instanceof EncryptedJWT encryptedJWT) {
                    Optional<SignedJWT> optionalSignedJWT = jsonWebTokenEncryption.decrypt(encryptedJWT);
                    if (optionalSignedJWT.isPresent()) {
                        jwt = optionalSignedJWT.get();
                    }
                }
                return Optional.of(jwt);
            } else {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("token {} does not contain two dots", token);
                }
            }
        } catch (final ParseException e) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Failed to parse JWT: {}", e.getMessage());
            }
        }
        return Optional.empty();
    }

    /**
     *
     * @param token The JWT string
     * @return {@literal true} if the string has at least two dots. We must have 2 (JWS) or 4 dots (JWE).
     */
    private boolean hasAtLeastTwoDots(String token) {
        return (token.contains(DOT)) &&
                (token.indexOf(DOT, token.indexOf(DOT) + 1) != -1);
    }
}
