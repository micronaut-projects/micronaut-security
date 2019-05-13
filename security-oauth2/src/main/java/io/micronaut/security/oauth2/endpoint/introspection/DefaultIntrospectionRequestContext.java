/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.oauth2.endpoint.introspection;

import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;

/**
 * Default implementation of {@link IntrospectionRequestContext}.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public class DefaultIntrospectionRequestContext implements IntrospectionRequestContext {
    protected final OauthClientConfiguration clientConfiguration;
    protected final SecureEndpoint introspectionEndpoint;

    /**
     *
     * @param introspectionEndpoint Intospection endpoint
     * @param clientConfiguration Client Configuration
     */
    public DefaultIntrospectionRequestContext(SecureEndpoint introspectionEndpoint,
                                              OauthClientConfiguration clientConfiguration) {
        this.introspectionEndpoint = introspectionEndpoint;
        this.clientConfiguration = clientConfiguration;
    }

    @Override
    public SecureEndpoint getEndpoint() {
        return introspectionEndpoint;
    }

    @Override
    public OauthClientConfiguration getClientConfiguration() {
        return clientConfiguration;
    }
}
