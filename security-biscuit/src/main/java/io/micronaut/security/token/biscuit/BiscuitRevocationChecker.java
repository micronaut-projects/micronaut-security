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

import io.micronaut.http.HttpRequest;
import org.biscuitsec.biscuit.token.Biscuit;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * Checks Biscuit revocation identifiers.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
public interface BiscuitRevocationChecker {

    /**
     * @param biscuit The verified Biscuit token
     * @param revocationIdentifiers The token revocation identifiers
     * @param request The HTTP request
     * @return True if the token is revoked
     */
    boolean isRevoked(Biscuit biscuit, List<String> revocationIdentifiers, @Nullable HttpRequest<?> request);
}
