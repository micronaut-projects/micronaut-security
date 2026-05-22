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
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.Authorizer;
import org.biscuitsec.biscuit.token.Biscuit;
import org.jspecify.annotations.Nullable;

/**
 * Customizes a Biscuit authorizer before authorization runs.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
public interface BiscuitAuthorizerCustomizer {

    /**
     * Customize the authorizer for a request.
     * @param authorizer The authorizer
     * @param biscuit The verified Biscuit token
     * @param request The HTTP request
     * @throws Error If customization fails
     */
    void customize(Authorizer authorizer, Biscuit biscuit, @Nullable HttpRequest<?> request) throws Error;
}
