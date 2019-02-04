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

package io.micronaut.security.oauth2.openid.providers;

import io.micronaut.context.annotation.Primary;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.annotation.Value;
import io.micronaut.core.util.StringUtils;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.endpoints.LogoutController;
import io.micronaut.security.endpoints.LogoutControllerConfiguration;
import io.micronaut.security.endpoints.LogoutControllerConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import io.micronaut.security.oauth2.openid.configuration.OpenIdConfiguration;
import io.micronaut.security.oauth2.openid.endpoints.endsession.EndSessionEndpointConfiguration;
import io.micronaut.security.oauth2.openid.endpoints.endsession.EndSessionEndpointConfigurationProperties;
import io.micronaut.security.oauth2.openid.endpoints.endsession.EndSessionParameter;
import io.micronaut.security.oauth2.openid.endpoints.endsession.EndSessionParameterType;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.inject.Singleton;
import java.util.ArrayList;
import java.util.List;

/**
 * Provides specific configuration to logout from Auth0.
 *
 * @see <a href="https://auth0.com/docs/logout/guides/logout-auth0">Log Users Out of Auth0</a>
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Requires(beans = {
        LogoutControllerConfiguration.class,
        OpenIdConfiguration.class,
        EmbeddedServer.class,
        LogoutController.class,
        EndSessionEndpointConfigurationProperties.class
})
@Requires(property = OauthConfigurationProperties.PREFIX + ".end-session.auth0.enabled", notEquals = StringUtils.FALSE)
@Requires(condition = Auth0OpenidConfigurationCondition.class)
@Primary
@Singleton
public class Auth0EndSessionEndpointConfiguration implements EndSessionEndpointConfiguration {

    private final String auth0Version;
    private final String logoutUri;
    private final String domainName;
    private final EndSessionEndpointConfigurationProperties endSessionEndpointConfigurationProperties;

    /**
     *
     * @param embeddedServer Embedded Server
     * @param domainName AWS Cognito User's pool domain Name
     * @param auth0Version Auth0 api version
     * @param logoutPath {@link LogoutController} path.
     * @param endSessionEndpointConfigurationProperties Default {@link io.micronaut.context.annotation.ConfigurationProperties} implementation of {@link EndSessionEndpointConfiguration}.
     */
    public Auth0EndSessionEndpointConfiguration(
            EmbeddedServer embeddedServer,
            @Value("${micronaut.security.oauth2.domain-name}") String domainName,
            @Value("${" + OauthConfigurationProperties.PREFIX + ".end-session.auth0.version:v2}") String auth0Version,
            @Value("${" + LogoutControllerConfigurationProperties.PREFIX + ".path:/logout}") String logoutPath,
            EndSessionEndpointConfigurationProperties endSessionEndpointConfigurationProperties) {
        this.auth0Version = auth0Version;
        this.domainName = domainName;
        this.logoutUri = embeddedServer.getURL().toString() + logoutPath;
        this.endSessionEndpointConfigurationProperties = endSessionEndpointConfigurationProperties;
    }

    @Nonnull
    @Override
    public List<EndSessionParameter> getParameters() {
        List<EndSessionParameter> endSessionParameters = new ArrayList<>();

        EndSessionParameter client = new EndSessionParameter();
        client.setName("client_id");
        client.setType(EndSessionParameterType.CLIENT_ID);
        endSessionParameters.add(client);

        EndSessionParameter logoutUriParam = new EndSessionParameter();
        logoutUriParam.setName("returnTo");
        logoutUriParam.setValue(getRedirectUri());
        endSessionParameters.add(logoutUriParam);

        return endSessionParameters;
    }

    @Nullable
    @Override
    public String getRedirectUri() {
        return endSessionEndpointConfigurationProperties.getRedirectUri() != null ?
                endSessionEndpointConfigurationProperties.getRedirectUri() :
                logoutUri;
    }

    @Nullable
    @Override
    public String getUrl() {
        return this.domainName + "/" + auth0Version + "/logout";
    }
}


