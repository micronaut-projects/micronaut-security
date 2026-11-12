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
class SiteminderAuthenticationFetcher implements AuthenticationFetcher<HttpRequest<?>> {

    public static final String SITEMINDER_USER_HEADER = "SM_USER"

    @Override
    Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
        Mono.<Authentication>create(emitter -> {
            String siteminderUser = request.headers.get(SITEMINDER_USER_HEADER)
            if (StringUtils.isEmpty(siteminderUser)) {
                emitter.success()
                return
            }

            Collection<String> roles = Collections.singleton("ROLE_USER")
            emitter.success(Authentication.build(siteminderUser, roles))
        })
    }
}
//end::clazz[]
