plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    api(projects.micronautSecurity)
    compileOnly(mn.micronaut.http)

    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(mnTest.micronaut.test.junit5)
    testRuntimeOnly(libs.junit.jupiter.engine)
    testRuntimeOnly(mnLogging.logback.classic)
}

tasks.withType<Test> {
    useJUnitPlatform()
}

micronautBuild {
    binaryCompatibility.enabled = false
}