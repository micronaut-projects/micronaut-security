plugins {
    `java-library`
    id("io.micronaut.build.internal.security-tests")
}

// This module intentionally does NOT depend on micronaut-session nor micronaut-security-session.
// It verifies micronaut-security-csrf behaves correctly when only the cookie-based CSRF repository is available.
dependencies {
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(mn.micronaut.http.client)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(projects.micronautSecurityCsrf)
    testImplementation(projects.micronautSecurityJwt)
    testImplementation(projects.testSuiteUtilsSecurity)
    testAnnotationProcessor(mnSerde.micronaut.serde.processor)
    testImplementation(mnSerde.micronaut.serde.jackson)

    testRuntimeOnly(mnLogging.logback.classic)
    testImplementation(mnTest.micronaut.test.junit5)
    testRuntimeOnly(mnTest.junit.jupiter.engine)
}

tasks.withType<Test> {
    useJUnitPlatform()
}
