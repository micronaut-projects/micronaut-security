plugins {
    id("java-library")
    id("io.micronaut.build.internal.security-tests")
}

dependencies {
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(libs.junit.jupiter.api)
    testImplementation(mnTest.micronaut.test.junit5)
    testRuntimeOnly(libs.junit.jupiter.engine)
    testRuntimeOnly(mnLogging.logback.classic)

    testImplementation(projects.micronautSecurityJwt)
    testImplementation(projects.micronautSecurityJwt)
    testImplementation(libs.managed.jjwt.api)
    testRuntimeOnly(libs.managed.jjwt.impl)
    testRuntimeOnly(libs.managed.jjwt.jackson)
}
tasks.withType<Test> {
    useJUnitPlatform()
}