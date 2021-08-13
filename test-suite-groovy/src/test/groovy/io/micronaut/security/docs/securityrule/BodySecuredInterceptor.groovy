package io.micronaut.security.docs.securityrule;

//tag::clazz[]

import io.micronaut.aop.InterceptorBean;
import io.micronaut.aop.MethodInterceptor;
import io.micronaut.aop.MethodInvocationContext;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthorizationException;
import io.micronaut.security.filters.SecurityFilter;

import java.util.Map;
import java.util.Optional;

@InterceptorBean(BodySecured.class)
class BodySecuredInterceptor implements MethodInterceptor<Object, Object> {

    @Override
    Object intercept(MethodInvocationContext<Object, Object> context) {
        Optional<HttpRequest<Object>> requestOptional = ServerRequestContext.currentRequest()
        Authentication authentication = null
        if (requestOptional.isPresent()) {
            HttpRequest<Object> request = requestOptional.get()
            authentication = request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class).orElse(null)
            if (isAllowed(request, authentication)) {
                return context.proceed()
            } else {
                boolean forbidden = authentication != null
                request.setAttribute(SecurityFilter.REJECTION, forbidden ? HttpStatus.FORBIDDEN : HttpStatus.UNAUTHORIZED)
            }
        }
        throw new AuthorizationException(authentication)
    }

    @NonNull
    private static boolean isAllowed(HttpRequest<?> request, @Nullable Authentication authentication) {
        request.getBody(Map)
                .filter(m -> m['name'] == 'George R.R. Martin')
                .isPresent()
    }
}
//end::clazz[]