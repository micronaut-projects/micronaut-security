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
import io.micronaut.security.oauth2.client.OauthClient;
import io.micronaut.security.oauth2.client.OpenIdClient;
import io.micronaut.security.oauth2.url.CallbackUrlBuilder;
import io.micronaut.security.oauth2.url.LoginUrlBuilder;
import io.micronaut.security.oauth2.url.LogoutUrlBuilder;
import io.micronaut.web.router.DefaultRouteBuilder;

import javax.inject.Singleton;
import java.util.List;

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

    /**
     * @param executionHandleLocator The execution handler locator
     * @param uriNamingStrategy The URI naming strategy
     * @param conversionService The conversion service
     * @param beanContext The bean context
     * @param callbackUrlBuilder The callback URL builder
     * @param loginUrlBuilder The login URL builder
     * @param logoutUrlBuilder The logout URL builder
     * @param controllerList The list of controllers
     */
    OauthRouteBuilder(ExecutionHandleLocator executionHandleLocator,
                             UriNamingStrategy uriNamingStrategy,
                             ConversionService<?> conversionService,
                             BeanContext beanContext,
                             CallbackUrlBuilder callbackUrlBuilder,
                             LoginUrlBuilder loginUrlBuilder,
                             LogoutUrlBuilder logoutUrlBuilder,
                             List<OauthController> controllerList) {
        super(executionHandleLocator, uriNamingStrategy, conversionService);

        controllerList.forEach((controller) -> {
            OauthClient client = controller.getClient();
            String name = client.getName();

            BeanDefinition<OauthController> bd = beanContext.getBeanDefinition(OauthController.class, Qualifiers.byName(name));

            bd.findMethod("login", HttpRequest.class).ifPresent(m -> {
                String loginPath = loginUrlBuilder.getPath(name);
                buildRoute(HttpMethod.GET, loginPath, ExecutionHandle.of(controller, m));
            });

            bd.findMethod("callback", HttpRequest.class).ifPresent(m -> {
                String callbackPath = callbackUrlBuilder.getPath(name);
                MethodExecutionHandle<OauthController, Object> executionHandle = ExecutionHandle.of(controller, m);
                buildRoute(HttpMethod.GET, callbackPath, executionHandle);
                buildRoute(HttpMethod.POST, callbackPath, executionHandle).consumes(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
            });

            if (client instanceof OpenIdClient) {
                if (((OpenIdClient) client).supportsEndSession()) {
                    bd.findMethod("logout", HttpRequest.class).ifPresent(m -> {
                        String logoutPath = logoutUrlBuilder.getPath(name);
                        buildRoute(HttpMethod.GET, logoutPath, ExecutionHandle.of(controller, m));
                    });
                }
            }
        });

    }
}
