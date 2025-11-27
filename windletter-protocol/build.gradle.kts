val jcsVersion: String by rootProject.extra
val junitVersion: String by rootProject.extra

dependencies {
    api(project(":windletter-core"))
    implementation(project(":windletter-crypto"))

    api("io.github.erdtman:java-json-canonicalization:$jcsVersion")
    api("com.fasterxml.jackson.core:jackson-databind:2.17.1")
    testImplementation("io.github.erdtman:java-json-canonicalization:$jcsVersion")

    testImplementation(platform("org.junit:junit-bom:$junitVersion"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}
