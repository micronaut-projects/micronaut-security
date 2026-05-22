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
package io.micronaut.security.token.macaroons;

import com.github.nitram509.jmacaroons.CaveatPacket;
import com.github.nitram509.jmacaroons.Macaroon;
import com.github.nitram509.jmacaroons.MacaroonsVerifier;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.config.TokenConfigurationProperties;
import io.micronaut.security.token.validator.TokenValidator;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.micronaut.security.utils.LoggingUtils.debug;

/**
 * Macaroon token validator.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
@Requires(property = TokenConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@Requires(property = MacaroonConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@Requires(property = MacaroonConfigurationProperties.PREFIX + ".validator-enabled", notEquals = StringUtils.FALSE)
@Requires(property = MacaroonConfigurationProperties.PREFIX + ".secret")
@Singleton
public class MacaroonTokenValidator implements TokenValidator<HttpRequest<?>> {

    private static final Logger LOG = LoggerFactory.getLogger(MacaroonTokenValidator.class);

    private final MacaroonConfiguration configuration;
    private final MacaroonAuthenticationFactory authenticationFactory;
    private final List<MacaroonCaveatVerifier> caveatVerifiers;

    /**
     * @param configuration Macaroon configuration
     * @param authenticationFactory Authentication factory
     * @param caveatVerifiers Application-specific caveat verifiers
     */
    public MacaroonTokenValidator(MacaroonConfiguration configuration,
                                  MacaroonAuthenticationFactory authenticationFactory,
                                  List<MacaroonCaveatVerifier> caveatVerifiers) {
        this.configuration = configuration;
        this.authenticationFactory = authenticationFactory;
        this.caveatVerifiers = caveatVerifiers;
    }

    @Override
    @SingleResult
    public Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
        for (MacaroonSerialization serialization : configuration.getAcceptedSerializations()) {
            Optional<Authentication> authentication = deserialize(token, serialization)
                .flatMap(macaroon -> validate(macaroon, serialization, request));
            if (authentication.isPresent()) {
                return Publishers.just(authentication.get());
            }
        }
        return Publishers.empty();
    }

    private Optional<Macaroon> deserialize(String token, MacaroonSerialization serialization) {
        try {
            return Optional.of(Macaroon.deserialize(token, MacaroonSerializers.serializer(serialization)));
        } catch (RuntimeException e) {
            debug(LOG, "Macaroon deserialization failed for {} format", serialization);
            return Optional.empty();
        }
    }

    private Optional<Authentication> validate(Macaroon macaroon,
                                              MacaroonSerialization serialization,
                                              @Nullable HttpRequest<?> request) {
        String secret = configuration.getSecret();
        if (StringUtils.isEmpty(secret)) {
            return Optional.empty();
        }

        List<MacaroonCaveat> caveats = firstPartyCaveats(macaroon);
        Map<String, Object> claims = new LinkedHashMap<>();
        MacaroonsVerifier verifier = new MacaroonsVerifier(macaroon);

        for (MacaroonCaveat caveat : caveats) {
            Optional<MacaroonClaimsCodec.DecodedClaim> decodedClaim = MacaroonClaimsCodec.decodeClaim(caveat.getValue());
            if (decodedClaim.isPresent()) {
                MacaroonClaimsCodec.DecodedClaim claim = decodedClaim.get();
                if (claims.containsKey(claim.key())) {
                    debug(LOG, "Macaroon validation failed because a claim caveat was duplicated");
                    return Optional.empty();
                }
                claims.put(claim.key(), claim.value());
                verifier.satisfyExact(caveat.getValue());
            } else if (verifyCaveat(caveat, request)) {
                verifier.satisfyExact(caveat.getValue());
            }
        }

        if (!validTimeClaims(claims)) {
            debug(LOG, "Macaroon validation failed because a time caveat is not satisfied");
            return Optional.empty();
        }

        try {
            if (!verifier.isValid(secret)) {
                debug(LOG, "Macaroon validation failed");
                return Optional.empty();
            }
        } catch (RuntimeException e) {
            debug(LOG, "Macaroon validation failed: {}", e.getClass().getSimpleName());
            return Optional.empty();
        }

        MacaroonAuthenticationContext context = new MacaroonAuthenticationContext(
            macaroon.location,
            macaroon.identifier,
            serialization,
            claims,
            caveats
        );
        return authenticationFactory.createAuthentication(context);
    }

    private boolean verifyCaveat(MacaroonCaveat caveat, @Nullable HttpRequest<?> request) {
        for (MacaroonCaveatVerifier verifier : caveatVerifiers) {
            try {
                if (verifier.verify(caveat, request)) {
                    return true;
                }
            } catch (RuntimeException e) {
                debug(LOG, "Macaroon caveat verifier failed: {}", e.getClass().getSimpleName());
                return false;
            }
        }
        return false;
    }

    private static boolean validTimeClaims(Map<String, Object> claims) {
        Instant now = Instant.now();
        if (claims.containsKey(Claims.EXPIRATION_TIME)) {
            Object expiration = claims.get(Claims.EXPIRATION_TIME);
            if (!(expiration instanceof Date date) || !now.isBefore(date.toInstant())) {
                return false;
            }
        }
        if (claims.containsKey(Claims.NOT_BEFORE)) {
            Object notBefore = claims.get(Claims.NOT_BEFORE);
            return notBefore instanceof Date date && !now.isBefore(date.toInstant());
        }
        return true;
    }

    private static List<MacaroonCaveat> firstPartyCaveats(Macaroon macaroon) {
        List<MacaroonCaveat> caveats = new ArrayList<>();
        CaveatPacket[] caveatPackets = macaroon.caveatPackets;
        if (caveatPackets == null) {
            return caveats;
        }
        int i = 0;
        while (i < caveatPackets.length) {
            CaveatPacket caveatPacket = caveatPackets[i];
            if (caveatPacket.getType() == CaveatPacket.Type.cid) {
                boolean thirdParty = i + 1 < caveatPackets.length && caveatPackets[i + 1].getType() == CaveatPacket.Type.vid;
                if (thirdParty) {
                    i += 2;
                    continue;
                } else {
                    caveats.add(new MacaroonCaveat(caveatPacket.getValueAsText()));
                }
            }
            i++;
        }
        return caveats;
    }
}
