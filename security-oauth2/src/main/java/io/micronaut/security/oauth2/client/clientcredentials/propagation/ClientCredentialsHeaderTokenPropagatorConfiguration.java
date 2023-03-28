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
package io.micronaut.security.oauth2.client.clientcredentials.propagation;

import io.micronaut.core.util.Toggleable;
import io.micronaut.http.HttpHeaderValues;
import io.micronaut.http.HttpHeaders;

/**
 * HTTP header client credentials token propagation configuration.
 *
 * @author Sergio del Amo
 * @since 2.2.0
 */
public interface ClientCredentialsHeaderTokenPropagatorConfiguration extends Toggleable {

    boolean DEFAULT_ENABLED = true;
    String DEFAULT_PREFIX = HttpHeaderValues.AUTHORIZATION_PREFIX_BEARER;
    String DEFAULT_HEADER_NAME = HttpHeaders.AUTHORIZATION;

    /**
     * @return a Prefix before the token in the header value. E.g. Bearer.
     */
    String getPrefix();

    /**
     * @return an HTTP Header name. e.g. Authorization.
     */
    String getHeaderName();

}
