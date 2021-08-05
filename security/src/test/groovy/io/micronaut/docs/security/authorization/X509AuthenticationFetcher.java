package io.micronaut.docs.security.authorization;

//tag::clazz[]
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.AuthenticationFetcher;
import org.reactivestreams.Publisher;
import io.micronaut.core.annotation.NonNull;
import jakarta.inject.Singleton;
import reactor.core.publisher.Mono;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
//end::clazz[]
@Requires(property = "spec.name", value = "X509AuthorizationSpec")
//tag::clazz[]
@Singleton
public class X509AuthenticationFetcher implements AuthenticationFetcher {

    @Override
    public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
        return Mono.<Authentication>create(emitter -> {
            Optional<Certificate> optionalCertificate = request.getCertificate();
            if (optionalCertificate.isPresent()) {
                Certificate certificate = optionalCertificate.get();
                if (certificate instanceof X509Certificate) {
                    emitter.success(new Authentication() {
                        X509Certificate x509Certificate = ((X509Certificate) certificate);
                        @Override
                        public String getName() {
                            return x509Certificate.getIssuerX500Principal().getName();
                        }

                        @NonNull
                        @Override
                        public Map<String, Object> getAttributes() {
                            return Collections.emptyMap();
                        }
                    });
                    return;
                }
            }
            emitter.success();
        });
    }
}
//end::clazz[]
