/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.security.token.paseto.validator;

import dev.paseto.jpaseto.PasetoParserBuilder;
import io.micronaut.core.annotation.NonNull;

/**
 * Returns a {@link PasetoParserBuilder} which will be used to parse/verify a Paseto token.
 * @author Sergio del Amo
 * @since 3.2.0
 */
@FunctionalInterface
public interface PasetoParserBuilderGenerator {

    /**
     *
     * @return a {@link PasetoParserBuilder} which will be used to sign a Paseto token.
     */
    @NonNull
    PasetoParserBuilder builder();
}
