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
package io.micronaut.security.handlers;

/**
 * Responsible for logging the user out and returning
 * an appropriate response.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 * @param <I> Request
 * @param <O> Response
 */
@FunctionalInterface
public interface LogoutHandler<I, O> {

    /**
     * @param request The HTTP Request being executed
     * @return An HttpResponse built after the user logs out
     */
    O logout(I request);
}
