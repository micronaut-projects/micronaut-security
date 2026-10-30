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
package io.micronaut.security.csrf.validator;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csrf.generator.CsrfHmacTokenGenerator;
import io.micronaut.security.csrf.repository.CsrfTokenRepository;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.security.MessageDigest;

/**
 * {@link CsrfTokenValidator} implementation that uses a {@link CsrfTokenRepository}.
 * The repositories are consulted following their {@link io.micronaut.core.order.Ordered} order. The first repository which holds a CSRF token for the request is authoritative:
 * the supplied token must match the token stored in that repository. Other repositories are not consulted, so that a token planted in a lower precedence
 * repository (for example a CSRF cookie planted by an attacker) cannot replace the token stored in a higher precedence repository (for example the HTTP session).
 * @param <T> Request
 * @since 4.11.0
 * @author Sergio del Amo
 */
@Requires(beans = { CsrfTokenRepository.class, CsrfHmacTokenGenerator.class})
@Internal
@Singleton
class RepositoryCsrfTokenValidator<T> implements CsrfTokenValidator<T> {
    private static final Logger LOG = LoggerFactory.getLogger(RepositoryCsrfTokenValidator.class);
    private final List<CsrfTokenRepository<T>> repositories;
    private final CsrfHmacTokenGenerator<T> defaultCsrfTokenGenerator;

    /**
     *
     * @param repositories CSRF Token Repositories
     * @param defaultCsrfTokenGenerator Default CSRF Token Generator
     */
    public RepositoryCsrfTokenValidator(List<CsrfTokenRepository<T>> repositories,
                                        CsrfHmacTokenGenerator<T> defaultCsrfTokenGenerator) {
        this.repositories = repositories;
        this.defaultCsrfTokenGenerator = defaultCsrfTokenGenerator;
    }

    @Override
    public boolean validateCsrfToken(T request, String csrfTokenInRequest) {
        for (CsrfTokenRepository<T> repo : repositories) {
            Optional<String> csrfTokenOptional = repo.findCsrfToken(request);
            if (csrfTokenOptional.isPresent()) {
                String csrfTokenInRepository = csrfTokenOptional.get();
                return csrfTokenInRepository.equals(csrfTokenInRequest) && validateHmac(request, csrfTokenInRequest);
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("No CSRF token found in any CSRF token repository");
        }
        return false;
    }

    private boolean validateHmac(T request, String csrfTokenInRequest) {
        String[] arr = csrfTokenInRequest.split("\\" + CsrfHmacTokenGenerator.HMAC_RANDOM_SEPARATOR);
        if (arr.length != 2) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("Invalid CSRF token: {}", csrfTokenInRequest);
            }
            return false;
        }
        String hmac = arr[0];
        String randomValue = arr[1];
        String expectedHmac = defaultCsrfTokenGenerator.hmac(request, randomValue);
        return MessageDigest.isEqual(expectedHmac.getBytes(StandardCharsets.UTF_8), hmac.getBytes(StandardCharsets.UTF_8));
    }
}
