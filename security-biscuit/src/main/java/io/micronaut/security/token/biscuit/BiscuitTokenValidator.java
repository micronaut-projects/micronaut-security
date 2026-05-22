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
package io.micronaut.security.token.biscuit;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.config.TokenConfigurationProperties;
import io.micronaut.security.token.validator.TokenValidator;
import io.vavr.control.Option;
import jakarta.inject.Singleton;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.datalog.RunLimits;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.Authorizer;
import org.biscuitsec.biscuit.token.Biscuit;
import org.biscuitsec.biscuit.token.RevocationIdentifier;
import org.biscuitsec.biscuit.token.builder.Utils;
import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static io.micronaut.security.utils.LoggingUtils.debug;

/**
 * Validates Biscuit bearer tokens.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
@Requires(property = TokenConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@Requires(property = BiscuitConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@Requires(property = BiscuitConfigurationProperties.PREFIX + ".validator-enabled", notEquals = StringUtils.FALSE)
@Singleton
public class BiscuitTokenValidator implements TokenValidator<HttpRequest<?>> {

    private static final Logger LOG = LoggerFactory.getLogger(BiscuitTokenValidator.class);

    private final BiscuitConfiguration configuration;
    private final BiscuitRootKeyLocator rootKeyLocator;
    private final BiscuitAuthenticationFactory authenticationFactory;
    private final List<BiscuitAuthorizerCustomizer> authorizerCustomizers;
    private final List<BiscuitRevocationChecker> revocationCheckers;

    /**
     * @param configuration Biscuit configuration
     * @param rootKeyLocator Root public key locator
     * @param authenticationFactory Authentication factory
     * @param authorizerCustomizers Authorizer customizers
     * @param revocationCheckers Revocation checkers
     */
    public BiscuitTokenValidator(BiscuitConfiguration configuration,
                                 BiscuitRootKeyLocator rootKeyLocator,
                                 BiscuitAuthenticationFactory authenticationFactory,
                                 List<BiscuitAuthorizerCustomizer> authorizerCustomizers,
                                 List<BiscuitRevocationChecker> revocationCheckers) {
        this.configuration = configuration;
        this.rootKeyLocator = rootKeyLocator;
        this.authenticationFactory = authenticationFactory;
        this.authorizerCustomizers = authorizerCustomizers;
        this.revocationCheckers = revocationCheckers;
    }

    @Override
    @SingleResult
    public Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
        if (configuration.getPolicies().isEmpty() && authorizerCustomizers.isEmpty()) {
            debug(LOG, "Biscuit validation skipped because no authorizer policy is configured");
            return Publishers.empty();
        }
        Optional<Biscuit> biscuit = deserialize(token);
        if (biscuit.isEmpty()) {
            return Publishers.empty();
        }

        try {
            List<String> revocationIdentifiers = revocationIdentifiers(biscuit.get());
            if (isRevoked(biscuit.get(), revocationIdentifiers, request)) {
                debug(LOG, "Biscuit validation failed because a revocation identifier is revoked");
                return Publishers.empty();
            }

            Authorizer authorizer = biscuit.get().authorizer();
            addRequestFacts(authorizer, request);
            addConfiguredAuthorizerElements(authorizer);
            for (BiscuitAuthorizerCustomizer customizer : authorizerCustomizers) {
                customizer.customize(authorizer, biscuit.get(), request);
            }
            long policyIndex = authorizer.authorize(runLimits(configuration));
            BiscuitAuthenticationContext context = new BiscuitAuthenticationContext(
                biscuit.get(),
                authorizer,
                policyIndex,
                revocationIdentifiers,
                request
            );
            return authenticationFactory.createAuthentication(context)
                .<Publisher<Authentication>>map(Publishers::just)
                .orElseGet(Publishers::empty);
        } catch (Error | RuntimeException e) {
            debug(LOG, "Biscuit validation failed: {}", e.getClass().getSimpleName());
            return Publishers.empty();
        }
    }

    static RunLimits runLimits(BiscuitConfiguration configuration) {
        BiscuitConfiguration.RunLimitsConfiguration runLimits = configuration.getRunLimits();
        return new RunLimits(runLimits.getMaxFacts(), runLimits.getMaxIterations(), runLimits.getMaxTime());
    }

    private Optional<Biscuit> deserialize(String token) {
        try {
            if (!BiscuitSignatureValidator.hasCanonicalSignatures(token)) {
                debug(LOG, "Biscuit deserialization failed because the token contains a non-canonical signature");
                return Optional.empty();
            }
            return Optional.of(Biscuit.from_b64url(token, keyId -> {
                Optional<PublicKey> rootKey = rootKeyLocator.findRootKey(keyId.isDefined() ? keyId.get() : null);
                return rootKey.map(Option::some).orElseGet(Option::none);
            }));
        } catch (Error | NoSuchAlgorithmException | SignatureException | InvalidKeyException | RuntimeException e) {
            debug(LOG, "Biscuit deserialization failed: {}", e.getClass().getSimpleName());
            return Optional.empty();
        }
    }

    private void addRequestFacts(Authorizer authorizer, @Nullable HttpRequest<?> request) throws Error {
        authorizer.set_time();
        if (request != null) {
            authorizer.add_fact(Utils.fact("resource", List.of(Utils.string(request.getPath()))));
            authorizer.add_fact(Utils.fact("operation", List.of(Utils.string(request.getMethod().toString()))));
        }
    }

    private void addConfiguredAuthorizerElements(Authorizer authorizer) throws Error {
        for (String fact : configuration.getFacts()) {
            authorizer.add_fact(fact);
        }
        for (String rule : configuration.getRules()) {
            authorizer.add_rule(rule);
        }
        for (String check : configuration.getChecks()) {
            authorizer.add_check(check);
        }
        for (String policy : configuration.getPolicies()) {
            authorizer.add_policy(policy);
        }
    }

    private boolean isRevoked(Biscuit biscuit, List<String> revocationIdentifiers, @Nullable HttpRequest<?> request) {
        for (BiscuitRevocationChecker revocationChecker : revocationCheckers) {
            if (revocationChecker.isRevoked(biscuit, revocationIdentifiers, request)) {
                return true;
            }
        }
        return false;
    }

    private static List<String> revocationIdentifiers(Biscuit biscuit) {
        List<String> identifiers = new ArrayList<>();
        for (RevocationIdentifier revocationIdentifier : biscuit.revocation_identifiers()) {
            identifiers.add(revocationIdentifier.toHex());
        }
        return identifiers;
    }
}
