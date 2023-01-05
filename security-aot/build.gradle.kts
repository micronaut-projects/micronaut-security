plugins {
    id("io.micronaut.build.internal.security-module")
    id("io.micronaut.build.internal.aot-module")
}

micronautBuild {
    aot {
        version.set("2.0.0-SNAPSHOT")
    }
}

micronautBuild {
    binaryCompatibility {
        enabled.set(false)
    }
}

dependencies {
    compileOnly(platform(mn.micronaut.core.bom))
    implementation(projects.securityOauth2)
    implementation(projects.securityJwt)
    testImplementation(platform(mn.micronaut.core.bom))
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(projects.securityOauth2)
    testImplementation(mnTest.micronaut.test.spock) {
        exclude("org.codehaus.groovy", "groovy-all")
    }
}
