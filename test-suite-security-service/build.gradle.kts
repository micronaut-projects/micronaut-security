plugins {
    id("java-library")
    id("io.micronaut.build.internal.security-tests")
}

dependencies {
    testAnnotationProcessor(mn.micronaut.inject.java)

    testRuntimeOnly(mnLogging.logback.classic)

    testImplementation(libs.junit.jupiter.api)
    testImplementation(mnTest.micronaut.test.junit5)
    testRuntimeOnly(libs.junit.jupiter.engine)

    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mn.micronaut.http.client)

    testAnnotationProcessor(mnSerde.micronaut.serde.processor)
    testImplementation(mnSerde.micronaut.serde.jackson)

    testAnnotationProcessor(projects.micronautSecurityAnnotations)
    testImplementation(projects.micronautSecurity)

    testAnnotationProcessor(mnData.micronaut.data.processor)
    testImplementation(mnData.micronaut.data.hibernate.reactive)

    testImplementation(mnSql.vertx.mysql.client)
    testImplementation(mnSql.mysql.connector.java)

    testImplementation(mnTestResources.testcontainers.core)
    testImplementation(mnTestResources.testcontainers.mysql)

    testImplementation(mnReactor.micronaut.reactor)
    // Test Fails without this dependency
    testImplementation(mnReactor.micrometer.context.propagation)
}
tasks.withType<Test> {
    useJUnitPlatform()
}