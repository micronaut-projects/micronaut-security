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
package io.micronaut.security.oauth2.routes;

import io.micronaut.context.BeanContext;
import io.micronaut.context.ExecutionHandleLocator;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.convert.ConversionService;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.inject.BeanDefinition;
import io.micronaut.inject.ExecutionHandle;
import io.micronaut.inject.MethodExecutionHandle;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.client.OauthClient;
import io.micronaut.security.oauth2.client.OpenIdClient;
import io.micronaut.security.oauth2.configuration.OauthConfiguration;
import io.micronaut.security.oauth2.url.OauthRouteUrlBuilder;
import io.micronaut.web.router.DefaultRouteBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Registers routes dynamically for OAuth 2.0 authorization
 * redirects, authorization callbacks, and end session redirects.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
@Internal
class OauthRouteBuilder extends DefaultRouteBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(OauthRouteBuilder.class);

    /**
     * @param executionHandleLocator The execution handler locator
     * @param uriNamingStrategy The URI naming strategy
     * @param conversionService The conversion service
     * @param beanContext The bean context
     * @param oauthConfiguration Oauth configuration
     * @param oauthRouteUrlBuilder The oauth URL builder
     * @param controllerList The list of controllers
     */
    OauthRouteBuilder(ExecutionHandleLocator executionHandleLocator,
                      UriNamingStrategy uriNamingStrategy,
                      ConversionService<?> conversionService,
                      BeanContext beanContext,
                      OauthConfiguration oauthConfiguration,
                      OauthRouteUrlBuilder oauthRouteUrlBuilder,
                      List<OauthController> controllerList) {
        super(executionHandleLocator, uriNamingStrategy, conversionService);

        if (controllerList.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No Oauth controllers found. Skipping registration of routes");
            }
        } else {
            AtomicBoolean endSessionRegistered = new AtomicBoolean();

            controllerList.forEach((controller) -> {
                OauthClient client = controller.getClient();
                String name = client.getName();
                boolean isDefaultProvider = oauthConfiguration.getDefaultProvider().filter(provider -> provider.equals(name)).isPresent();

                BeanDefinition<OauthController> bd = beanContext.getBeanDefinition(OauthController.class, Qualifiers.byName(name));

                bd.findMethod("login", HttpRequest.class).ifPresent(m -> {
                    String loginPath = oauthRouteUrlBuilder.buildLoginUri(name).getPath();
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Registering login route [GET: {}] for oauth configuration [{}]", loginPath, name);
                    }
                    buildRoute(HttpMethod.GET, loginPath, ExecutionHandle.of(controller, m));
                    if (isDefaultProvider) {
                        final String defaultLoginPath = oauthRouteUrlBuilder.buildLoginUri(null).getPath();
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Registering default login route [GET: {}] for oauth configuration [{}]", defaultLoginPath, name);
                        }
                        buildRoute(HttpMethod.GET, defaultLoginPath, ExecutionHandle.of(controller, m));
                    }
                });

                bd.findMethod("callback", HttpRequest.class).ifPresent(m -> {
                    String callbackPath = oauthRouteUrlBuilder.buildCallbackUri(name).getPath();
                    MethodExecutionHandle<OauthController, Object> executionHandle = ExecutionHandle.of(controller, m);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Registering callback route [GET: {}] for oauth configuration [{}]", callbackPath, name);
                        LOG.debug("Registering callback route [POST: {}] for oauth configuration [{}]", callbackPath, name);
                    }
                    buildRoute(HttpMethod.GET, callbackPath, executionHandle);
                    buildRoute(HttpMethod.POST, callbackPath, executionHandle).consumes(MediaType.APPLICATION_FORM_URLENCODED_TYPE);

                    if (isDefaultProvider) {
                        final String defaultCallbackPath = oauthRouteUrlBuilder.buildCallbackUri(null).getPath();
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Registering default callback route [GET: {}] for oauth configuration [{}]", defaultCallbackPath, name);
                            LOG.debug("Registering default callback route [POST: {}] for oauth configuration [{}]", defaultCallbackPath, name);
                        }
                        buildRoute(HttpMethod.GET, defaultCallbackPath, executionHandle);
                        buildRoute(HttpMethod.POST, defaultCallbackPath, executionHandle).consumes(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
                    }
                });

                if (client instanceof OpenIdClient) {

                    if (((OpenIdClient) client).supportsEndSession() && endSessionRegistered.compareAndSet(false, true)) {
                        beanContext.findExecutionHandle(EndSessionController.class, "endSession", HttpRequest.class, Authentication.class).ifPresent(executionHandle -> {
                            String logoutUri = oauthConfiguration.getOpenid().getLogoutUri();

                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Registering end session route [GET: {}]", logoutUri);
                            }
                            buildRoute(HttpMethod.GET, logoutUri, executionHandle);
                        });
                    }
                }
            });

            if (!endSessionRegistered.get() && LOG.isDebugEnabled()) {
                LOG.debug("Skipped registration of logout route. No openid clients found that support end session");
            }
        }
    }
}
