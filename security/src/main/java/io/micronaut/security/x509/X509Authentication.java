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

import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.authentication.ServerAuthentication;

import java.security.cert.X509Certificate;

/**
 * An Authentication derived from an X509Certificate.
 *
 * @author Burt Beckwith
 * @since 3.3
 */
public class X509Authentication extends ServerAuthentication {

    @NonNull
    private final X509Certificate certificate;

    public X509Authentication(@NonNull X509Certificate certificate, @NonNull String name) {
        super(name, null, null);
        this.certificate = certificate;
    }

    /**
     * @return the X.509 certificate
     */
    @NonNull
    public X509Certificate getCertificate() {
        return certificate;
    }
}
