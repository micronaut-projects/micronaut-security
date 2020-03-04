/*
 * Copyright 2017-2020 original authors
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

package io.micronaut.security.oauth2.routes;

import io.micronaut.context.BeanContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.ProviderResolver;
import io.micronaut.security.oauth2.client.OpenIdClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.util.Optional;

/**
 * A controller for the end session endpoint.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
public class DefaultEndSessionController implements EndSessionController {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultEndSessionController.class);

    private final ProviderResolver providerResolver;
    private final BeanContext beanContext;

    /**
     * @param providerResolver The provider resolver
     * @param beanContext The bean context
     */
    public DefaultEndSessionController(ProviderResolver providerResolver,
                                       BeanContext beanContext) {
        this.providerResolver = providerResolver;
        this.beanContext = beanContext;
    }

    /**
     * Performs and end session redirect to an OpenID provider.
     *
     * @param request The current request
     * @param authentication The current authentication
     * @return A redirecting http response
     */
    @Override
    public Optional<MutableHttpResponse<?>> endSession(HttpRequest<?> request, Authentication authentication) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Received logout request for user [{}]", authentication.getName());
        }
        return providerResolver.resolveProvider(authentication)
                .flatMap(p -> beanContext.findBean(OpenIdClient.class, Qualifiers.byName(p)))
                .filter(OpenIdClient::supportsEndSession)
                .flatMap(c -> c.endSessionRedirect(request, authentication));
    }
}
