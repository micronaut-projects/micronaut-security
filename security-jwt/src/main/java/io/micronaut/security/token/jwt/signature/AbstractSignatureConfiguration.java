/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.token.jwt.signature;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.Internal;

/**
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Internal
public abstract class AbstractSignatureConfiguration implements SignatureConfiguration<SignedJWT, JWSAlgorithm> {

    protected JWSAlgorithm algorithm = JWSAlgorithm.HS256;

    /**
     *
     * @return {@link JWSAlgorithm}
     */
    public JWSAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * algorithm Setter.
     * @param algorithm Instance of {@link JWSAlgorithm}
     */
    public void setAlgorithm(final JWSAlgorithm algorithm) {
        this.algorithm = algorithm;
    }
}
