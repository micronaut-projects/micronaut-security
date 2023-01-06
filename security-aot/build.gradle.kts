plugins {
    id("io.micronaut.build.internal.security-module")
    id("io.micronaut.build.internal.aot-module")
}

micronautBuild {
    aot {
        version.set("2.0.0-SNAPSHOT")
    }
}

dependencies {
    annotationProcessor(platform(mn.micronaut.core.bom))
    compileOnly(platform(mn.micronaut.core.bom))
    implementation(projects.securityOauth2)
    implementation(projects.securityJwt)
    testImplementation(platform(mn.micronaut.core.bom))
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mnTest.micronaut.test.spock) {
        exclude("org.codehaus.groovy", "groovy-all")
    }
}
