package io.micronaut.docs.security.authorization;

//tag::clazz[]

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.AuthenticationFetcher;
import jakarta.inject.Singleton;
import java.util.Collection;
import java.util.Collections;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
//end::clazz[]

@Requires(property = "spec.name", value = "SiteminderAuthorizationSpec")
//tag::clazz[]
@Singleton
public class SiteminderAuthenticationFetcher implements AuthenticationFetcher {

    public static final String SITEMINDER_USER_HEADER = "SM_USER";

    @Override
    public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
        return Mono.<Authentication>create(emitter -> {
            String siteminderUser = request.getHeaders().get(SITEMINDER_USER_HEADER);
            if (StringUtils.isEmpty(siteminderUser)) {
                emitter.success();
                return;
            }

            Collection<String> roles = Collections.singleton("ROLE_USER");
            emitter.success(Authentication.build(siteminderUser, roles));
        });
    }
}
//end::clazz[]
