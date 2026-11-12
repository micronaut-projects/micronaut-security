/*
 * Copyright 2017-2023 original authors
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
import io.micronaut.context.ExecutionHandleLocator;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.convert.ConversionService;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.inject.BeanDefinition;
import io.micronaut.inject.ExecutableMethod;
import io.micronaut.inject.ExecutionHandle;
import io.micronaut.inject.MethodExecutionHandle;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.client.OauthClient;
import io.micronaut.security.oauth2.client.OpenIdClient;
import io.micronaut.security.oauth2.configuration.OauthConfiguration;
import io.micronaut.security.oauth2.url.OauthRouteUrlBuilder;
import io.micronaut.web.router.DefaultRouteBuilder;
import jakarta.inject.Singleton;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.micronaut.security.utils.LoggingUtils.debug;

/**
 * Registers routes dynamically for OAuth 2.0 authorization
 * redirects, authorization callbacks, and end session redirects.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Requires(classes = DefaultRouteBuilder.class)
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
                      ConversionService conversionService,
                      BeanContext beanContext,
                      OauthConfiguration oauthConfiguration,
                      OauthRouteUrlBuilder oauthRouteUrlBuilder,
                      List<OauthController> controllerList) {
        super(executionHandleLocator, uriNamingStrategy, conversionService);

        if (controllerList.isEmpty()) {
            debug(LOG, "No Oauth controllers found. Skipping registration of routes");
        } else {
            AtomicBoolean endSessionRegistered = new AtomicBoolean();

            controllerList.forEach(controller -> {
                OauthClient client = controller.getClient();
                String name = client.getName();
                boolean isDefaultProvider = oauthConfiguration.getDefaultProvider().filter(provider -> provider.equals(name)).isPresent();

                BeanDefinition<OauthController> bd = beanContext.getBeanDefinition(OauthController.class, Qualifiers.byName(name));

                bd.findMethod("login", HttpRequest.class).ifPresent(m -> {
                    String loginPath = oauthRouteUrlBuilder.buildLoginUri(name).getPath();
                    debug(LOG, "Registering login route [GET: {}] for oauth configuration [{}]", loginPath, name);
                    @SuppressWarnings({"unchecked", "rawtypes"})
                    MethodExecutionHandle<Object, Object> executionHandle = ExecutionHandle.of(controller, (ExecutableMethod) m);
                    buildRoute(HttpMethod.GET, loginPath, executionHandle);
                    if (isDefaultProvider) {
                        final String defaultLoginPath = oauthRouteUrlBuilder.buildLoginUri(null).getPath();
                        debug(LOG, "Registering default login route [GET: {}] for oauth configuration [{}]", defaultLoginPath, name);
                        buildRoute(HttpMethod.GET, defaultLoginPath, executionHandle);
                    }
                });

                bd.findMethod("callback", HttpRequest.class).ifPresent(m -> {
                    String callbackPath = oauthRouteUrlBuilder.buildCallbackUri(name).getPath();
                    @SuppressWarnings({"unchecked", "rawtypes"})
                    MethodExecutionHandle<Object, Object> executionHandle = ExecutionHandle.of(controller, (ExecutableMethod) m);
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

                if (client instanceof OpenIdClient && ((OpenIdClient) client).supportsEndSession() && endSessionRegistered.compareAndSet(false, true)) {
                    beanContext.findExecutionHandle(EndSessionController.class, "endSession", HttpRequest.class, Authentication.class).ifPresent(executionHandle -> {
                        String logoutUri = oauthConfiguration.getOpenid().getLogoutUri();

                        debug(LOG, "Registering end session route [GET: {}]", logoutUri);
                        //noinspection unchecked,rawtypes
                        buildRoute(HttpMethod.GET, logoutUri, (MethodExecutionHandle) executionHandle);
                    });
                }
            });

            if (!endSessionRegistered.get() && LOG.isDebugEnabled()) {
                LOG.debug("Skipped registration of logout route. No openid clients found that support end session");
            }
        }
    }
}
