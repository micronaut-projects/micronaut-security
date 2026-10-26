plugins {
    id("io.micronaut.build.internal.security-module")
}
repositories {
    mavenLocal {
        mavenContent {
            snapshotsOnly()
        }
    }
}
dependencies {
    annotationProcessor(mnSerde.micronaut.serde.processor)
    annotationProcessor(mnValidation.micronaut.validation.processor)
    api("io.micronaut.supabase:micronaut-supabase:0.0.1-SNAPSHOT")
    api(mnSerde.micronaut.serde.api)
    api(mnValidation.validation) // jakarta.validation:jakarta.validation-api
    compileOnly(mn.micronaut.http.client.core)
    compileOnly(mnValidation.micronaut.validation)
    compileOnly(mn.jackson.databind)
    testImplementation(mnSerde.micronaut.serde.jackson)
    api(projects.micronautSecurity)
    testImplementation(mn.micronaut.http.client)
    testImplementation(projects.micronautSecurityJwt)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mnValidation.micronaut.validation)
    testImplementation(platform(mnTest.boms.testcontainers))
    testImplementation(libs.testcontainers)
    testImplementation(libs.testcontainers.junit.jupiter)
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.6.0")
}

