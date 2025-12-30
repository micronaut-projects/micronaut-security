plugins {
    id("io.micronaut.build.internal.kotlin-kapt")
    id("io.micronaut.build.internal.security-tests")
}

dependencies {
    testImplementation(platform(kotlin("bom")))
    testImplementation(kotlin("stdlib"))
    kaptTest(mn.micronaut.inject.java)
    kaptTest(projects.micronautSecurityProcessor)

    testImplementation(mnTest.junit.jupiter.api)
    testImplementation(mnTest.micronaut.test.junit5)
    testRuntimeOnly(mnTest.junit.jupiter.engine)

    testRuntimeOnly(mnLogging.logback.classic)
    testImplementation(mn.micronaut.management)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mn.micronaut.http.client)
    testImplementation(projects.micronautSecurityJwt)
    testImplementation(projects.micronautSecurityOauth2)
    testImplementation(projects.testSuiteUtils)
    testImplementation(projects.testSuiteUtilsSecurity)
    testImplementation(mnReactor.micronaut.reactor)

    testImplementation(mn.jackson.databind)
    kaptTest(mnSerde.micronaut.serde.processor)
    testImplementation(mnSerde.micronaut.serde.jackson)

    kaptTest(mnData.micronaut.data.processor)
    testImplementation(mnData.micronaut.data.jdbc)
    testImplementation(mnSql.h2)
    testImplementation(mnSql.micronaut.jdbc.hikari)
}
tasks.withType<Test> {
    useJUnitPlatform()
}
