/*
 * Copyright 2017-2018 original authors
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

@Singleton
public class DefaultRedirectUrlProvider {

    private final String defaultRedirectUri;

    public DefaultRedirectUrlProvider(EmbeddedServer embeddedServer,
                                      @Value("${" + AuthorizationCodeControllerConfigurationProperties.PREFIX + ".controller-path:/authcode}") String authorizationCodeControllerPath,
                                      @Value("${" + AuthorizationCodeControllerConfigurationProperties.PREFIX + ".action-path:/cb}") String authorizationCodeControllerActionPath) {
        this.defaultRedirectUri = embeddedServer.getURL().toString() + authorizationCodeControllerPath + authorizationCodeControllerActionPath;
    }

    public String getRedirectUri() {
        return defaultRedirectUri;
    }
}
