package io.micronaut.security.csrf.generator;

import io.micronaut.context.annotation.Property;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

@Property(name = "micronaut.security.csrf.signature-key", value = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
@MicronautTest(startApplication = false)
class CsrfTokenSignerTest {

    @Test
    void tokenIsSigned() {

    }

}