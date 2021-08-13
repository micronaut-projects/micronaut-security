package io.micronaut.security.docs.securityrule

import io.micronaut.aop.InterceptorBean
import io.micronaut.aop.MethodInterceptor
import io.micronaut.aop.MethodInvocationContext
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.context.ServerRequestContext
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthorizationException
import io.micronaut.security.filters.SecurityFilter

//tag::clazz[]
@InterceptorBean(BodySecured::class)
class BodySecuredInterceptor : MethodInterceptor<Any?, Any?> {
    override fun intercept(context: MethodInvocationContext<Any?, Any?>): Any? {
        val requestOptional = ServerRequestContext.currentRequest<Any>()
        var authentication: Authentication? = null
        if (requestOptional.isPresent) {
            val request = requestOptional.get()
            authentication = request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication::class.java).orElse(null)
            if (isAllowed(request, authentication)) {
                return context.proceed()
            } else {
                val forbidden = authentication != null
                request.setAttribute(SecurityFilter.REJECTION, if (forbidden) HttpStatus.FORBIDDEN else HttpStatus.UNAUTHORIZED)
            }
        }
        throw AuthorizationException(authentication)
    }

    private fun isAllowed(request: HttpRequest<*>, @Nullable authentication: Authentication?): Boolean {
        return request.getBody(MutableMap::class.java)
                .filter { m -> m.containsKey("name") && m["name"] == "George R.R. Martin" }
                .isPresent
    }
}