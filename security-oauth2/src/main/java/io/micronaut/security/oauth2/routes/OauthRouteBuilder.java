package io.micronaut.security.oauth2.routes;

import io.micronaut.context.BeanContext;
import io.micronaut.context.ExecutionHandleLocator;
import io.micronaut.core.convert.ConversionService;
import io.micronaut.core.naming.NameResolver;
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

@Singleton
public class OauthRouteBuilder extends DefaultRouteBuilder {

    public OauthRouteBuilder(ExecutionHandleLocator executionHandleLocator,
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
