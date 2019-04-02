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

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.uri.UriTemplate;
import io.micronaut.security.oauth2.configuration.OauthConfiguration;
import io.micronaut.security.oauth2.openid.endpoints.OpenIdEndpoints;
import io.micronaut.security.token.reader.TokenResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.annotation.Nonnull;
import javax.inject.Singleton;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Default implementation of {@link EndSessionUrlProvider}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Singleton
@Requires(beans = {TokenResolver.class, OpenIdEndpoints.class, OauthConfiguration.class, EndSessionEndpoint.class})
public class DefaultEndSessionUrlProvider implements EndSessionUrlProvider {
    private static final char OPENCURLYBRACE = '{';
    private static final char COMMA = ',';
    private static final char CLOSECURLYBRACE = '}';
    private static final char QUESTIONMARK = '?';
    private static final Logger LOG = LoggerFactory.getLogger(DefaultEndSessionUrlProvider.class);

    private final TokenResolver tokenResolver;
    private final OauthConfiguration oauthConfiguration;
    private final OpenIdEndpoints openIdEndpoints;
    private final EndSessionEndpoint endSessionEndpoint;

    /**
     *
     * @param tokenResolver Token Resolver
     * @param oauthConfiguration OAuth 2.0 Configuration
     * @param openIdEndpoints Open ID endpoints
     * @param endSessionEndpoint End-session endpoint configuration
     */
    public DefaultEndSessionUrlProvider(@Nonnull TokenResolver tokenResolver,
                                        @Nonnull OauthConfiguration oauthConfiguration,
                                        @Nonnull OpenIdEndpoints openIdEndpoints,
                                        @Nonnull EndSessionEndpoint endSessionEndpoint) {
        this.tokenResolver = tokenResolver;
        this.oauthConfiguration = oauthConfiguration;
        this.openIdEndpoints = openIdEndpoints;
        this.endSessionEndpoint = endSessionEndpoint;
    }

    @Override
    public String resolveLogoutUrl(HttpRequest<?> request) {
        String baseUrl = openIdEndpoints.getEndSession();
        String template = instantiateTemplate(baseUrl);
        UriTemplate uriTemplate = new UriTemplate(template);
        Map<String, Object> arguments = new HashMap<>();

        for (EndSessionParameter param : endSessionEndpoint.getParameters()) {
            String value = resolveValue(param, request);
            if (value != null) {
                arguments.put(param.getName(), value);
            }
        }
        String expandedUri = uriTemplate.expand(arguments);
        if (LOG.isDebugEnabled()) {
            LOG.debug("logout url {}", expandedUri);
        }
        return expandedUri;
    }

    /**
     *
     * @param param end-session parameter
     * @param request HTTP Request
     * @return The resolved value for the end-session parameter.
     */
    protected String resolveValue(EndSessionParameter param, HttpRequest<?> request) {

        if (param.getType() == EndSessionParameterType.IDTOKEN) {
            Optional<String> token = tokenResolver.resolveToken(request);
            return token.orElse(null);
        }
        if (param.getType() == EndSessionParameterType.CLIENT_ID) {
            return oauthConfiguration.getClientId();
        }
        if (param.getType() == EndSessionParameterType.CLIENT_SECRET) {
            return oauthConfiguration.getClientSecret();
        }
        return param.getValue();
    }

    /**
     *
     * @param baseUrl The base URL
     * @return A url encoded string with parameters
     */
    protected String instantiateTemplate(String baseUrl) {
        Optional<String> optionalUrlArguments = endSessionEndpoint.getParameters()
                .stream()
                .map(EndSessionParameter::getName)
                .reduce((a, b) -> a + COMMA + b);
        return optionalUrlArguments.map(s -> baseUrl + OPENCURLYBRACE + QUESTIONMARK + s + CLOSECURLYBRACE).orElse(baseUrl);
    }
}
