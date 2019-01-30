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

package io.micronaut.security.oauth2.openid.endpoints.endsession;

import io.micronaut.context.annotation.Primary;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.annotation.Value;
import io.micronaut.core.util.StringUtils;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.endpoints.LogoutControllerConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.inject.Singleton;
import java.util.ArrayList;
import java.util.List;

/**
 * Provides specific configuration to logout from AWS Cognito.
 *
 * @see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html">AWS Cognito Logout Endpoint</a>
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Requires(property = OauthConfigurationProperties.PREFIX + ".domain-name")
@Requires(property = OauthConfigurationProperties.PREFIX + ".end-session.aws-cognito.enabled", notEquals = StringUtils.FALSE)
@Requires(condition = AwsCognitoOpenidConfigurationCondition.class)
@Primary
@Singleton
public class AwsCognitoEndSessionEndpointConfiguration implements EndSessionEndpointConfiguration {

    private final String logoutUri;
    private final String domainName;

    /**
     *
     * @param embeddedServer Embedded Server
     * @param domainName AWS Cognito User's pool domain Name
     * @param logoutPath {@link io.micronaut.security.endpoints.LogoutController} path.
     */
    public AwsCognitoEndSessionEndpointConfiguration(
            EmbeddedServer embeddedServer,
            @Value("${micronaut.security.oauth2.domain-name}") String domainName,

            @Value("${" + LogoutControllerConfigurationProperties.PREFIX + ".path:/logout}") String logoutPath) {
        this.domainName = domainName;
        this.logoutUri = embeddedServer.getURL().toString() + logoutPath;
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
        logoutUriParam.setName("logout_uri");
        logoutUriParam.setValue(logoutUri);
        endSessionParameters.add(logoutUriParam);

        return endSessionParameters;
    }

    @Nullable
    @Override
    public String getUrl() {
        return this.domainName + "/logout";
    }
}


