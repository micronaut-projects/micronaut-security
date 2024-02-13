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
    testImplementation(projects.micronautSecurity)
    testImplementation(mn.micronaut.http.client)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mn.micronaut.jackson.databind)
    testImplementation(mnHibernateValidator.micronaut.hibernate.validator)
    testImplementation(platform(mnTest.boms.junit))
    testImplementation(libs.junit.jupiter.params)
}
tasks.withType<Test> {
    useJUnitPlatform()
}