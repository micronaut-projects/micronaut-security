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
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

/**
 * Performs strict Ed25519 signature encoding checks before delegating to Biscuit Java.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
final class BiscuitSignatureValidator {

    private static final int ED25519_SIGNATURE_LENGTH = 64;
    private static final int ED25519_ENCODED_POINT_LENGTH = 32;
    private static final int ED25519_SCALAR_OFFSET = 32;
    private static final int ED25519_SCALAR_LENGTH = 32;
    private static final int ED25519_SIGN_BIT_MASK = 0x80;
    private static final int ED25519_SIGN_BIT_OFFSET = 31;
    private static final BigInteger ED25519_FIELD_PRIME = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger ED25519_GROUP_ORDER = new BigInteger(
        "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
        16
    );
    private static final BigInteger ED25519_D = BigInteger.valueOf(-121665)
        .multiply(BigInteger.valueOf(121666).modInverse(ED25519_FIELD_PRIME))
        .mod(ED25519_FIELD_PRIME);
    private static final BigInteger ED25519_SQRT_M1 = BigInteger.TWO.modPow(
        ED25519_FIELD_PRIME.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)),
        ED25519_FIELD_PRIME
    );
    private static final BigInteger ED25519_SQRT_EXPONENT = ED25519_FIELD_PRIME
        .add(BigInteger.valueOf(3))
        .divide(BigInteger.valueOf(8));

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
        return isCanonicalEncodedPoint(bytes)
            && littleEndianToBigInteger(Arrays.copyOfRange(bytes, ED25519_SCALAR_OFFSET, ED25519_SIGNATURE_LENGTH)).compareTo(ED25519_GROUP_ORDER) < 0;
    }

    private static boolean isCanonicalEncodedPoint(byte[] signature) {
        byte[] encodedY = Arrays.copyOf(signature, ED25519_ENCODED_POINT_LENGTH);
        boolean xOdd = (encodedY[ED25519_SIGN_BIT_OFFSET] & ED25519_SIGN_BIT_MASK) != 0;
        encodedY[ED25519_SIGN_BIT_OFFSET] &= ~ED25519_SIGN_BIT_MASK;
        BigInteger y = littleEndianToBigInteger(encodedY);
        if (y.compareTo(ED25519_FIELD_PRIME) >= 0) {
            return false;
        }
        Optional<BigInteger> decodedX = recoverX(y);
        return decodedX
            .map(x -> x.signum() != 0 || !xOdd)
            .orElse(false);
    }

    private static Optional<BigInteger> recoverX(BigInteger y) {
        BigInteger ySquared = y.multiply(y).mod(ED25519_FIELD_PRIME);
        BigInteger numerator = ySquared.subtract(BigInteger.ONE).mod(ED25519_FIELD_PRIME);
        BigInteger denominator = ED25519_D.multiply(ySquared).add(BigInteger.ONE).mod(ED25519_FIELD_PRIME);
        if (denominator.signum() == 0) {
            return Optional.empty();
        }
        BigInteger xSquared = numerator.multiply(denominator.modInverse(ED25519_FIELD_PRIME)).mod(ED25519_FIELD_PRIME);
        BigInteger x = xSquared.modPow(ED25519_SQRT_EXPONENT, ED25519_FIELD_PRIME);
        if (!x.multiply(x).mod(ED25519_FIELD_PRIME).equals(xSquared)) {
            x = x.multiply(ED25519_SQRT_M1).mod(ED25519_FIELD_PRIME);
        }
        if (!x.multiply(x).mod(ED25519_FIELD_PRIME).equals(xSquared)) {
            return Optional.empty();
        }
        return Optional.of(x);
    }

    private static BigInteger littleEndianToBigInteger(byte[] littleEndian) {
        byte[] bigEndian = new byte[littleEndian.length];
        for (int i = 0; i < littleEndian.length; i++) {
            bigEndian[littleEndian.length - 1 - i] = littleEndian[i];
        }
        return new BigInteger(1, bigEndian);
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
