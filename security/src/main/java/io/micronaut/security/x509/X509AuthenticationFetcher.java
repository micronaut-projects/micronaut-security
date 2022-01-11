/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.x509;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.AuthenticationFetcher;
import io.micronaut.security.token.TokenAuthenticationFetcher;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.micronaut.core.util.StringUtils.TRUE;
import static java.util.regex.Pattern.CASE_INSENSITIVE;

/**
 * Creates an Authentication if an X.509 client certificate is present and a
 * name (CN) can be extracted.
 *
 * @author Burt Beckwith
 * @since 3.3
 */
@Singleton
@Requires(property = X509ConfigurationProperties.PREFIX + ".enabled", value = TRUE)
public class X509AuthenticationFetcher implements AuthenticationFetcher {

    /**
     * The order of the fetcher.
     */
    public static final int ORDER = TokenAuthenticationFetcher.ORDER - 200;

    private final Pattern subjectDnPattern;

    public X509AuthenticationFetcher(X509Configuration x509Configuration) {
        subjectDnPattern = Pattern.compile(x509Configuration.getSubjectDnRegex(), CASE_INSENSITIVE);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    @Override
    public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
        return Mono.create(emitter -> {
            Optional<Authentication> authentication = createAuthentication(request);
            emitter.success(authentication.orElse(null));
        });
    }

    /**
     * Creates an {@link X509Authentication} from information in an {@link X509Certificate}
     * if one is present in the request.
     *
     * @param request the request
     * @return the authentication if the certificate exists and contains a valid name
     */
    protected Optional<Authentication> createAuthentication(HttpRequest<?> request) {
        Optional<Certificate> optionalCertificate = request.getCertificate();
        if (optionalCertificate.isPresent()) {
            Certificate certificate = optionalCertificate.get();
            if (certificate instanceof X509Certificate) {
                return createX509Authentication((X509Certificate) certificate);
            }
        }
        return Optional.empty();
    }

    /**
     * Creates an {@link X509Authentication} from information in an {@link X509Certificate}.
     *
     * @param certificate the certificate
     * @return the authentication if the certificate contains a valid name
     */
    protected Optional<Authentication> createX509Authentication(@NonNull X509Certificate certificate) {
        final Optional<String> optionalName = extractName(certificate);
        return optionalName.map(name -> new X509Authentication(certificate, name));
    }

    /**
     * Extracts the name from the certificate using the subject DN regex.
     *
     * @param certificate the client certificate
     * @return the name if found
     */
    protected Optional<String> extractName(@NonNull X509Certificate certificate) {
        String subjectDN = certificate.getSubjectX500Principal().getName();

        Matcher matcher = subjectDnPattern.matcher(subjectDN);
        if (!matcher.find()) {
            return Optional.empty();
        }

        if (matcher.groupCount() != 1) {
            return Optional.empty();
        }

        return Optional.of(matcher.group(1));
    }
}
