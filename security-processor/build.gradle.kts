plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    compileOnly(mn.micronaut.core.processor)
    implementation(projects.micronautSecurityAnnotations)
    testImplementation(mn.micronaut.core.processor)
    testImplementation(mnTest.junit.jupiter.api)
    testImplementation(mnTest.mockito.core)
    testRuntimeOnly(mnTest.junit.jupiter.engine)
}

micronautBuild {
    binaryCompatibility {
        enabled.set(false)
    }
}
