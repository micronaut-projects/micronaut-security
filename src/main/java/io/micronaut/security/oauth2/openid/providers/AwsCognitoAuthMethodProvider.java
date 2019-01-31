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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.oauth2.openid.endpoints.token.AuthMethodProvider;
import io.micronaut.security.oauth2.openid.endpoints.token.TokenEndpointAuthMethod;
import io.micronaut.security.oauth2.openid.endpoints.token.TokenEndpointConfigurationProperties;

import javax.inject.Singleton;

/**
 * Provides authentication method for token endpoint and AWS Cognito.
 *
 * @see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html">Token Endpoint</a>
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Requires(property = TokenEndpointConfigurationProperties.PREFIX + ".auth-method-provider.cognito", notEquals = StringUtils.FALSE)
@Requires(condition = AwsCognitoOpenidConfigurationCondition.class)
@Singleton
public class AwsCognitoAuthMethodProvider implements AuthMethodProvider {
    @Override
    public TokenEndpointAuthMethod findAuthMethod() {
        return TokenEndpointAuthMethod.CLIENT_SECRET_BASIC;
    }
}
