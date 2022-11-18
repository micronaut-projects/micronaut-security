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
import io.micronaut.core.naming.Named;
import io.micronaut.core.order.Ordered;

import java.util.List;

/**
 * @author Sergio del Amo
 * @since 3.9.0
 */
public interface PkceGenerator extends Ordered, Named {
    /**
     *
     * @param codeChallengeMethods Code Challenge methods
     * @return Whether the PKCE Generator supports any of the supplied code challenge methods.
     */
    @NonNull
    boolean supportsAny(@NonNull List<String> codeChallengeMethods);

    /**
     *
     * @return Generates a {@link Pkce}.
     */
    @NonNull
    Pkce generate();
}
