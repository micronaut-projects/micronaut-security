/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.authentication.providers;

import org.reactivestreams.Publisher;

/**
 * Responsible for returning user information based
 * on their username.
 *
 * @author Sergio del Amo
 * @author Graeme Rocher
 * @since 1.0
 * @deprecated This class will be removed in a future version
 */
@Deprecated
public interface UserFetcher {

    /**
     * Fetches a user based on the username.
     *
     * @param username e.g. admin
     * @return The users information or an empty publisher if no user is present
     */
    Publisher<UserState> findByUsername(String username);
}
