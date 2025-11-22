val junitVersion: String by rootProject.extra

dependencies {
    api(project(":windletter-core"))
    implementation(project(":windletter-crypto"))
    implementation(project(":windletter-protocol"))
    implementation(project(":windletter-armor"))

    testImplementation(platform("org.junit:junit-bom:$junitVersion"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}
