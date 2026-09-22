package io.micronaut.security.docs.siteminder

//tag::clazz[]
import io.micronaut.context.annotation.Requires
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.filters.AuthenticationFetcher
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
//end::clazz[]

@Requires(property = "spec.name", value = "SiteminderAuthorizationTest")
//tag::clazz[]
@Singleton
class SiteminderAuthenticationFetcher : AuthenticationFetcher<HttpRequest<*>> {

    override fun fetchAuthentication(request: HttpRequest<*>): Publisher<Authentication> {
        return Mono.create { emitter ->
            val siteminderUser = request.headers[SITEMINDER_USER_HEADER]
            if (siteminderUser == null || StringUtils.isEmpty(siteminderUser)) {
                emitter.success()
                return@create
            }

            val roles: Collection<String> = setOf("ROLE_USER")
            emitter.success(Authentication.build(siteminderUser, roles))
        }
    }

    companion object {
        const val SITEMINDER_USER_HEADER = "SM_USER"
    }
}
//end::clazz[]
