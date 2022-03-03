/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.token.jwt.signature.rsa;

import com.nimbusds.jose.JWSAlgorithm;
import java.security.interfaces.RSAPrivateKey;

/**
 * Encapsulates RSA Signature Generation Configuration.
 * @author Sergio del Amo
 * @since 1.0
 */
public interface RSASignatureGeneratorConfiguration extends RSASignatureConfiguration {

    /**
     *
     * @return The RSA private Key
     */
    RSAPrivateKey getPrivateKey();

    /**
     * @return The JWS Algorithm
     */
    JWSAlgorithm getJwsAlgorithm();
}
