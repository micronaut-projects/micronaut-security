plugins {
    id 'java-library'
    id "io.micronaut.build.internal.security-tests"
}

dependencies {
    testAnnotationProcessor(platform(mn.micronaut.bom))
    testAnnotationProcessor(mn.micronaut.inject.java)

    testImplementation(platform(mn.micronaut.bom))
    testImplementation(libs.junit.jupiter.api)
    testImplementation(mn.micronaut.test.junit5)
    testRuntimeOnly(libs.junit.jupiter.engine)

    testRuntimeOnly(libs.logback.classic)
    testImplementation(mn.micronaut.management)
    testImplementation("io.micronaut.servlet:micronaut-http-server-tomcat")
    testImplementation(mn.micronaut.http.client)
    testImplementation project(":security-jwt")
    testImplementation project(":test-suite-utils-security")
    testImplementation(libs.reactor.core)
}

tasks.named('test') {
    useJUnitPlatform()
}

