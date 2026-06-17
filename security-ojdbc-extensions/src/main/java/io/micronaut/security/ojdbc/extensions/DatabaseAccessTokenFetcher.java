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
package io.micronaut.security.ojdbc.extensions;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.annotation.Internal;
import oracle.jdbc.spi.OracleResourceProvider;
import org.jspecify.annotations.NonNull;

import java.util.Map;

/**
 * Fetches OAuth 2.0 access tokens used by Oracle JDBC to access Oracle Database
 * on behalf of an authenticated Micronaut Security user.
 *
 * @since 5.1.0
 */
@Experimental
@Internal
public interface DatabaseAccessTokenFetcher {

    /**
     * Requests an OAuth 2.0 access token that authorizes the application to
     * access Oracle Database.
     *
     * @param parameters parameters supplied to the OJDBC resource provider
     *
     * @return a database access token
     *
     * @throws DatabaseAccessTokenFetcherException if a database access token cannot be obtained
     * @since 5.1.0
     */
    @NonNull
    String fetchDatabaseAccessToken(@NonNull Map<OracleResourceProvider.Parameter, CharSequence> parameters) throws DatabaseAccessTokenFetcherException;

}
