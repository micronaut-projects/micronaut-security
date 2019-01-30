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

package io.micronaut.security.oauth2.openid.endpoints.userinfo;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;

import javax.annotation.Nullable;

/**
 * {@link ConfigurationProperties} implementation of {@link UserInfoEndpointConfiguration}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@ConfigurationProperties(UserInfoEndpointConfigurationProperties.PREFIX)
public class UserInfoEndpointConfigurationProperties implements UserInfoEndpointConfiguration {
    public static final String PREFIX = OauthConfigurationProperties.PREFIX + ".user-info";

    @Nullable
    private String url;

    /**
     *
     * @return UserInfo endpoint Url.
     */
    @Nullable
    @Override
    public String getUrl() {
        return url;
    }

    /**
     * URL of the Open ID Provider's UserInfo Endpoint. This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
     * @param url UserInfo endpoint Url.
     */
    public void setUrl(@Nullable String url) {
        this.url = url;
    }
}
