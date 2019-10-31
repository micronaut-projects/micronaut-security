@Requires(property = OAUTH_TOKEN_AUTHORIZATION_CONFIG + ".enabled", notEquals = StringUtils.FALSE)
@Configuration
package io.micronaut.security.oauth2.bearer;

import io.micronaut.context.annotation.Configuration;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;

import static io.micronaut.security.oauth2.bearer.ClientCredentialsTokenValidator.OAUTH_TOKEN_AUTHORIZATION_CONFIG;
