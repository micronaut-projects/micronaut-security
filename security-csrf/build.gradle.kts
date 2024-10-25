plugins {
    id("io.micronaut.build.internal.security-module")
    jacoco
}

dependencies {
    api(projects.micronautSecurity)
    compileOnly(mn.micronaut.http.server)
    compileOnly(projects.micronautSecuritySession)
    implementation(mnReactor.micronaut.reactor)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(mnTest.micronaut.test.junit5)
    testRuntimeOnly(libs.junit.jupiter.engine)
    testRuntimeOnly(mnLogging.logback.classic)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mn.micronaut.http.client)
    testAnnotationProcessor(mnSerde.micronaut.serde.processor)
    testImplementation(mnSerde.micronaut.serde.jackson)
    testImplementation(projects.testSuiteUtilsSecurity)
    testImplementation(projects.micronautSecurityJwt)
    testImplementation(projects.micronautSecuritySession)
}

tasks.withType<Test> {
    useJUnitPlatform()
}

micronautBuild {
    binaryCompatibility.enabled = false
}
tasks.test {
    finalizedBy(tasks.jacocoTestReport) // report is always generated after tests run
}
tasks.jacocoTestReport {
    dependsOn(tasks.test) // tests are required to run before generating the report
    reports {
        xml.required = false
        csv.required = false
        html.outputLocation.set(layout.buildDirectory.dir("jacocoHtml"))
    }
}
tasks.jacocoTestCoverageVerification {
    enabled = true
    violationRules {
        rule {
            limit {
                minimum = "0".toBigDecimal()
            }
        }
    }
}

tasks.check {
    dependsOn(tasks.jacocoTestCoverageVerification)
}
