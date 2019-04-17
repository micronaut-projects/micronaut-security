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

package io.micronaut.security.oauth2.openid.endpoints;

import io.micronaut.context.annotation.Value;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.oauth2.endpoints.AuthorizationCodeControllerConfigurationProperties;
import javax.inject.Singleton;

/**
 * Utility bean to return the absolute URL to the {@link io.micronaut.security.oauth2.endpoints.AuthorizationCodeController}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Singleton
public class DefaultRedirectUrlProvider {

    private final String defaultRedirectUri;

    /**
     *
     * @param embeddedServer The embedded server
     * @param authorizationCodeControllerPath The root path of {@link io.micronaut.security.oauth2.endpoints.AuthorizationCodeController}.
     * @param authorizationCodeControllerActionPath The path to the actions of {@link io.micronaut.security.oauth2.endpoints.AuthorizationCodeController}.
     */
    public DefaultRedirectUrlProvider(EmbeddedServer embeddedServer,
                                      @Value("${" + AuthorizationCodeControllerConfigurationProperties.PREFIX + ".controller-path:/authcode}") String authorizationCodeControllerPath,
                                      @Value("${" + AuthorizationCodeControllerConfigurationProperties.PREFIX + ".action-path:/cb}") String authorizationCodeControllerActionPath) {

        this.defaultRedirectUri = getServerUrl(embeddedServer) + authorizationCodeControllerPath +
                authorizationCodeControllerActionPath;
    }

    /**
     * @param embeddedServer The embedded server
     * @return The URL where the Micronaut app server listens.
     */
    public String getServerUrl(EmbeddedServer embeddedServer) {
        return embeddedServer.getURL().toString();
    }

    /**
     *
     * @return Absolute URL to the {@link io.micronaut.security.oauth2.endpoints.AuthorizationCodeController}.
     */
    public String getRedirectUri() {
        return defaultRedirectUri;
    }
}
