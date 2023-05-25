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
package io.micronaut.security.errors;

import java.net.URI;
import java.util.Optional;

/**
 * Keep track of state before login.
 * @param <I> Request
 * @param <O> Response
 */
public interface PriorToLoginPersistence<I, O> {

    void onUnauthorized(I request, O response);

    Optional<URI> getOriginalUri(I request, O response);
}
