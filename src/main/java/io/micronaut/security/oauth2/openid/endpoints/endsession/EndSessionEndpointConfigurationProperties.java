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

package io.micronaut.security.oauth2.openid.endpoints.endsession;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;

/**
 * {@link ConfigurationProperties} implementation of {@link EndSessionEndpointConfiguration}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@ConfigurationProperties(EndSessionEndpointConfigurationProperties.PREFIX)
public class EndSessionEndpointConfigurationProperties implements EndSessionEndpointConfiguration {

    public static final String PREFIX = OauthConfigurationProperties.PREFIX + ".end-session";

    @Nullable
    private String url;

    @Nonnull
    private List<EndSessionParameter> parameters = new ArrayList<>();

    @Nonnull
    @Override
    public List<EndSessionParameter> getParameters() {
        return parameters;
    }

    /**
     *
     * @param parameters End-session endpoint parameters.
     */
    public void setParameters(@Nonnull List<EndSessionParameter> parameters) {
        this.parameters = parameters;
    }

    @Nullable
    @Override
    public String getUrl() {
        return url;
    }

    /**
     *
     * @param url The end-session endpoint url
     */
    public void setUrl(@Nullable String url) {
        this.url = url;
    }

}
