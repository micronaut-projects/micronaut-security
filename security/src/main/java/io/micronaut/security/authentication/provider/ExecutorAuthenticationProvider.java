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
package io.micronaut.security.authentication.provider;

import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.AuthenticationRequest;

/**
 * An {@link AuthenticationProvider} which forces you to define the executor to be used.
 * Blocking implementations of AuthenticationProvider should use this API.
 * @author Sergio del Amo
 * @since 4.5.0
 * @param <T> Request Context Type
 * @param <I> Authentication Request Identity Type
 * @param <S> Authentication Request Secret Type
 */
public interface ExecutorAuthenticationProvider<T, I, S> extends AuthenticationProvider<T, I, S>  {

    /**
     *
     * @return The executor name where the code {@link AuthenticationProvider#authenticate(T, AuthenticationRequest)} will be executed.
     */
    default String getExecutorName() {
        return TaskExecutors.BLOCKING;
    }
}
