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

import io.micronaut.security.authentication.AbstractPrincipalArgumentBinder;
import jakarta.inject.Singleton;

/**
 * Binds the authentication if it's an {@link X509Authentication} to a route argument.
 *
 * @author Burt Beckwith
 * @since 3.3
 */
@Singleton
public class X509AuthenticationArgumentBinder extends AbstractPrincipalArgumentBinder<X509Authentication> {

    public X509AuthenticationArgumentBinder() {
        super(X509Authentication.class);
    }
}
