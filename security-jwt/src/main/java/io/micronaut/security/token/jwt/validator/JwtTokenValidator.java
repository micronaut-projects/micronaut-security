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
package io.micronaut.security.token.jwt.validator;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.validator.TokenValidator;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.util.Collection;
import java.util.concurrent.ExecutorService;

/**
 * @see <a href="https://connect2id.com/products/nimbus-jose-jwt/examples/validating-jwt-access-tokens">Validating JWT Access Tokens</a>
 *
 * @author Sergio del Amo
 * @since 1.0
 * @param <T> Request
 * @deprecated Use {@link ReactiveJsonWebTokenValidator} instead.
 */
@Deprecated
public class JwtTokenValidator<T> implements TokenValidator<T> {

    protected final JwtAuthenticationFactory jwtAuthenticationFactory;
    protected final JwtValidator<T> validator;
    private final Scheduler scheduler;

    /**
     * Constructor.
     *
     * @param signatureConfigurations List of Signature configurations which are used to attempt validation.
     * @param encryptionConfigurations List of Encryption configurations which are used to attempt validation.
     * @param genericJwtClaimsValidators Generic JWT Claims validators which should be used to validate any JWT.
     * @param jwtAuthenticationFactory Utility to generate an Authentication given a JWT.
     * @param executorService Executor Service
     */
    @Inject
    public JwtTokenValidator(Collection<SignatureConfiguration> signatureConfigurations,
                             Collection<EncryptionConfiguration> encryptionConfigurations,
                             Collection<GenericJwtClaimsValidator> genericJwtClaimsValidators,
                             JwtAuthenticationFactory jwtAuthenticationFactory,
                             @Named(TaskExecutors.BLOCKING) ExecutorService executorService) {
        this(JwtValidator.builder()
                .withSignatures(signatureConfigurations)
                .withEncryptions(encryptionConfigurations)
                .withClaimValidators(genericJwtClaimsValidators)
                .build(), jwtAuthenticationFactory, Schedulers.fromExecutorService(executorService));
    }

    /**
     * Constructor.
     *
     * @param signatureConfigurations List of Signature configurations which are used to attempt validation.
     * @param encryptionConfigurations List of Encryption configurations which are used to attempt validation.
     * @param genericJwtClaimsValidators Generic JWT Claims validators which should be used to validate any JWT.
     * @param jwtAuthenticationFactory Utility to generate an Authentication given a JWT.
     * @deprecated Use {@link #JwtTokenValidator(Collection, Collection, Collection, JwtAuthenticationFactory, ExecutorService)} instead.
     */
    @Deprecated
    public JwtTokenValidator(Collection<SignatureConfiguration> signatureConfigurations,
                             Collection<EncryptionConfiguration> encryptionConfigurations,
                             Collection<GenericJwtClaimsValidator> genericJwtClaimsValidators,
                             JwtAuthenticationFactory jwtAuthenticationFactory) {
        this(JwtValidator.builder()
                .withSignatures(signatureConfigurations)
                .withEncryptions(encryptionConfigurations)
                .withClaimValidators(genericJwtClaimsValidators)
                .build(), jwtAuthenticationFactory);
    }

    /**
     * @param validator Validates the JWT
     * @param jwtAuthenticationFactory The authentication factory
     * @deprecated Use {@link #JwtTokenValidator(JwtValidator, JwtAuthenticationFactory, Scheduler)} instead.
     */
    @Deprecated
    public JwtTokenValidator(JwtValidator<T> validator,
                             JwtAuthenticationFactory jwtAuthenticationFactory) {
        this(validator, jwtAuthenticationFactory, Schedulers.boundedElastic());
    }

    /**
     * @param validator Validates the JWT
     * @param jwtAuthenticationFactory The authentication factory
     * @param scheduler The scheduler to use
     */
    public JwtTokenValidator(JwtValidator<T> validator,
                             JwtAuthenticationFactory jwtAuthenticationFactory,
                             Scheduler scheduler) {
        this.validator = validator;
        this.jwtAuthenticationFactory = jwtAuthenticationFactory;
        this.scheduler = scheduler;
    }

    /***
     * @param token The token string.
     * @return Publishes {@link Authentication} based on the JWT or empty if the validation fails.
     */
    @Override
    public Publisher<Authentication> validateToken(String token, @Nullable T request) {
        return Mono.fromCallable(() -> validator.validate(token, request))
            .flatMap(tokenOptional -> tokenOptional.flatMap(jwtAuthenticationFactory::createAuthentication)
                .map(Mono::just).orElse(Mono.empty())).subscribeOn(scheduler);
    }
}
