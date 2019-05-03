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
package io.micronaut.security.oauth2.url;

import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;

import javax.inject.Singleton;

/**
 * Builds a URL to log in with an OAuth 2.0 provider.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
public class LoginUrlBuilder extends AbstractUrlBuilder {

    /**
     * @param hostResolver The host resolver
     * @param oauthConfigurationProperties The configuration
     */
    LoginUrlBuilder(HostResolver hostResolver,
                    OauthConfigurationProperties oauthConfigurationProperties) {
        super(hostResolver, oauthConfigurationProperties.getLoginUri());
    }

}
