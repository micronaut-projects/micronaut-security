plugins {
    id("io.micronaut.build.internal.security-module")
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.1.0")
    testFramework = io.micronaut.build.TestFramework.JUNIT6
}
dependencies {
    api(mnSql.ojdbc11)
    api(projects.micronautSecurity)

    testAnnotationProcessor(mn.micronaut.inject.java)

    // HTTP Server
    testImplementation(mn.micronaut.http.server.netty)

    // HTTP Client
    testImplementation(mn.micronaut.http.client)

    // Data
    testAnnotationProcessor(mnData.micronaut.data.processor)
    testImplementation(mnData.micronaut.data.jdbc)

    // Database migration
    testImplementation(mnLiquibase.micronaut.liquibase)

    // Connection Pool
    testImplementation(mnSql.micronaut.jdbc.hikari)

    // Serialization
    annotationProcessor(mnSerde.micronaut.serde.processor)
    implementation(mnSerde.micronaut.serde.jackson)

    testImplementation(mn.micronaut.http)

    testImplementation(platform(mnTest.boms.testcontainers))
    testImplementation(libs.testcontainers.oracle.free)
}
