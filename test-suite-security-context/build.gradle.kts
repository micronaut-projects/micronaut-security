plugins {
    `java-library`
    id("io.micronaut.build.internal.security-tests")
}
dependencies {
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(libs.junit.jupiter.api)
    testImplementation(mnTest.micronaut.test.junit5)
    testRuntimeOnly(libs.junit.jupiter.engine)
    testRuntimeOnly(mnLogging.logback.classic)
    testImplementation(projects.micronautSecurity)
}
tasks.withType<Test> {
    useJUnitPlatform()
}
