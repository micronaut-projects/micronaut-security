/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.token.biscuit;

import biscuit.format.schema.Schema;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import java.math.BigInteger;
import java.util.Base64;

/**
 * Performs strict Ed25519 signature encoding checks before delegating to Biscuit Java.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
final class BiscuitSignatureValidator {

    private static final int ED25519_SIGNATURE_LENGTH = 64;
    private static final int ED25519_SCALAR_OFFSET = 32;
    private static final int ED25519_SCALAR_LENGTH = 32;
    private static final BigInteger ED25519_GROUP_ORDER = new BigInteger(
        "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
        16
    );

    private BiscuitSignatureValidator() {
    }

    static boolean hasCanonicalSignatures(String token) {
        try {
            return hasCanonicalSignatures(Schema.Biscuit.parseFrom(Base64.getUrlDecoder().decode(padBase64Url(token))));
        } catch (IllegalArgumentException | InvalidProtocolBufferException e) {
            return false;
        }
    }

    private static boolean hasCanonicalSignatures(Schema.Biscuit biscuit) {
        if (!biscuit.hasAuthority() || !hasCanonicalSignatures(biscuit.getAuthority())) {
            return false;
        }
        for (Schema.SignedBlock block : biscuit.getBlocksList()) {
            if (!hasCanonicalSignatures(block)) {
                return false;
            }
        }
        return !biscuit.hasProof()
            || !biscuit.getProof().hasFinalSignature()
            || isCanonicalEd25519Signature(biscuit.getProof().getFinalSignature());
    }

    private static boolean hasCanonicalSignatures(Schema.SignedBlock block) {
        if (!block.hasSignature() || !isCanonicalEd25519Signature(block.getSignature())) {
            return false;
        }
        return !block.hasExternalSignature()
            || !block.getExternalSignature().hasSignature()
            || isCanonicalEd25519Signature(block.getExternalSignature().getSignature());
    }

    private static boolean isCanonicalEd25519Signature(ByteString signature) {
        if (signature.size() != ED25519_SIGNATURE_LENGTH) {
            return false;
        }
        byte[] bytes = signature.toByteArray();
        byte[] scalar = new byte[ED25519_SCALAR_LENGTH];
        for (int i = 0; i < ED25519_SCALAR_LENGTH; i++) {
            scalar[ED25519_SCALAR_LENGTH - 1 - i] = bytes[ED25519_SCALAR_OFFSET + i];
        }
        return new BigInteger(1, scalar).compareTo(ED25519_GROUP_ORDER) < 0;
    }

    private static String padBase64Url(String token) {
        int remainder = token.length() % 4;
        return switch (remainder) {
            case 0 -> token;
            case 2 -> token + "==";
            case 3 -> token + "=";
            default -> token;
        };
    }
}
