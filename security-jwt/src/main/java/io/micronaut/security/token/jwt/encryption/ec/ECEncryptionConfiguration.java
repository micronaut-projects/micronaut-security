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
package io.micronaut.security.token.jwt.encryption.ec;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * @author Sergio del Amo
 * @since 1.0
 */
public interface ECEncryptionConfiguration {

    /**
     *
     * @return EC Public Key
     */
    ECPublicKey getPublicKey();

    /**
     *
     * @return EC Private Key
     */
    ECPrivateKey getPrivateKey();

    /**
     * @return The JWE algorithm
     */
    JWEAlgorithm getJweAlgorithm();

    /**
     *
     * @return {@link EncryptionMethod}
     */
    EncryptionMethod getEncryptionMethod();
}
