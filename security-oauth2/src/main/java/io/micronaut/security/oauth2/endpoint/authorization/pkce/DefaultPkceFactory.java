/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.oauth2.endpoint.authorization.pkce;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.PkcePersistence;
import jakarta.inject.Singleton;

import java.util.List;
import java.util.Optional;

/**
 * Generates a Proof Key for Code Exchange and persists.
 * @author Sergio del Amo
 * @since 3.9.0
 */
@Singleton
public class DefaultPkceFactory implements PkceFactory {
    @NonNull
    private final List<PkceGenerator> generators;

    @NonNull
    private final PkcePersistence persistence;

    public DefaultPkceFactory(@NonNull List<PkceGenerator> generators,
                              @NonNull PkcePersistence persistence) {
        this.generators = generators;
        this.persistence = persistence;
    }

    @Override
    @NonNull
    public Optional<PkceChallenge> buildChallenge(@NonNull HttpRequest<?> request,
                                                  @NonNull MutableHttpResponse<?> response,
                                                  @Nullable List<String> supportedChallengeMethods) {
        if (CollectionUtils.isEmpty(generators) || CollectionUtils.isEmpty(supportedChallengeMethods)) {
            return Optional.empty();
        }
        Optional<Pkce> pkceOptional = generators.stream()
            .filter(gen -> gen.supportsAny(supportedChallengeMethods))
            .map(PkceGenerator::generate)
            .findFirst();
        pkceOptional.ifPresent(chal -> persistence.persistPkce(request, response, chal));
        return pkceOptional.map(PkceChallenge.class::cast);
    }
}
