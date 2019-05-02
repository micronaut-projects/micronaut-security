package io.micronaut.security.oauth2.routes;

import io.micronaut.context.BeanContext;
import io.micronaut.context.ExecutionHandleLocator;
import io.micronaut.core.convert.ConversionService;
import io.micronaut.core.naming.NameResolver;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.url.CallbackUrlBuilder;
import io.micronaut.security.oauth2.url.LoginUrlBuilder;
import io.micronaut.web.router.DefaultRouteBuilder;

import javax.inject.Singleton;

@Singleton
public class OauthRouteBuilder extends DefaultRouteBuilder {

    public OauthRouteBuilder(ExecutionHandleLocator executionHandleLocator,
                             UriNamingStrategy uriNamingStrategy,
                             ConversionService<?> conversionService,
                             BeanContext beanContext,
                             CallbackUrlBuilder callbackUrlBuilder,
                             LoginUrlBuilder loginUrlBuilder) {
        super(executionHandleLocator, uriNamingStrategy, conversionService);

        beanContext.getBeanDefinitions(OauthController.class).forEach(bd -> {
            if (bd instanceof NameResolver) {
                ((NameResolver) bd).resolveName().ifPresent(name -> {
                    String loginPath = loginUrlBuilder.getPath(name);
                    String callbackPath = callbackUrlBuilder.getPath(name);

                    bd.findMethod("login", HttpRequest.class).ifPresent(m ->
                            GET(loginPath, bd, m));

                    bd.findMethod("callback", HttpRequest.class).ifPresent(m -> {
                        POST(callbackPath, bd, m).consumes(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
                        GET(callbackPath, bd, m);
                    });

                });
            }
        });

    }
}
