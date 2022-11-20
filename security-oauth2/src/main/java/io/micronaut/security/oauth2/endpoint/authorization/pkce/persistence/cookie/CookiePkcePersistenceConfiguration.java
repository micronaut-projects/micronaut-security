/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.cookie;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.oauth2.endpoint.authorization.pkce.PkceConfigurationProperties;
import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.oauth2.endpoint.AbstractCookieConfiguration;

/**
 * @author Nemanja Mikic
 * @since 3.9.0
 */
@ConfigurationProperties(CookiePkcePersistenceConfiguration.PREFIX)
public class CookiePkcePersistenceConfiguration extends AbstractCookieConfiguration {
    public static final String PREFIX = PkceConfigurationProperties.PREFIX + ".cookie";

    private static final String DEFAULT_COOKIE_NAME = "OAUTH2_PKCE";

    /**
     * Cookie Name. Default value `{@link #DEFAULT_COOKIE_NAME}`.
     *
     * @param cookieName Cookie name
     */
    @Override
    public void setCookieName(@NonNull String cookieName) {
        this.cookieName = cookieName;
    }

    @Override
    public String defaultCookieName() {
        return DEFAULT_COOKIE_NAME;
    }
}
