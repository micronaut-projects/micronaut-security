plugins {
    id("io.micronaut.build.internal.security-module")
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.1.0")
    testFramework = io.micronaut.build.TestFramework.JUNIT6
}
repositories {
    exclusiveContent {
        forRepository {
            mavenLocal()
        }
        filter {
            includeModule(
                "com.oracle.database.jdbc",
                "ojdbc-extensions"
            )
            includeModule(
                "com.oracle.database.jdbc",
                "ojdbc-provider-common"
            )
        }
    }
}
dependencies {
    implementation(mnSql.ojdbc11)
    implementation(libs.managed.ojdbc.provider.common)
    implementation(mn.micronaut.http.client.core)
    implementation(mnReactor.micronaut.reactor)
    implementation(projects.micronautSecurityOauth2)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(projects.micronautSecurityJwt)
    testImplementation(libs.managed.nimbus.jose.jwt)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mn.micronaut.http.client)
    annotationProcessor(mnSerde.micronaut.serde.processor)
    implementation(mnSerde.micronaut.serde.jackson)
}
