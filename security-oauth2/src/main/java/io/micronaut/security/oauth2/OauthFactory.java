package io.micronaut.security.oauth2;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.security.oauth2.client.DefaultOauthClient;
import io.micronaut.security.oauth2.client.OauthClient;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRedirectUrlBuilder;
import io.micronaut.security.oauth2.endpoint.authorization.response.OauthAuthorizationResponseHandler;
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper;

@Factory
public class OauthFactory {

    @EachBean(OauthClientConfiguration.class)
    OauthClient oauthClient(@Parameter OauthClientConfiguration clientConfiguration,
                            @Parameter OauthUserDetailsMapper userDetailsMapper,
                            AuthorizationRedirectUrlBuilder redirectUrlBuilder,
                            OauthAuthorizationResponseHandler authorizationResponseHandler,
                            BeanContext beanContext) {
        if (clientConfiguration.isEnabled()) {
            if (clientConfiguration.getAuthorization().flatMap(EndpointConfiguration::getUrl).isPresent()) {
                if (clientConfiguration.getToken().flatMap(EndpointConfiguration::getUrl).isPresent()) {
                    return new DefaultOauthClient(clientConfiguration, userDetailsMapper, redirectUrlBuilder, authorizationResponseHandler, beanContext);
                }
            }
        }
        return null;
    }
}
