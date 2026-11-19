# Maven 3.9.16, Temurin JDK 21.0.12.1; digest pins the multi-platform base.
FROM maven:3.9-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320 AS build
WORKDIR /build
COPY pom.xml .
COPY src src
RUN mvn -B -ntp package dependency:copy-dependencies -DincludeScope=runtime
COPY generate-keys.sh .
RUN sh generate-keys.sh /build/test-keys

FROM maven:3.9-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320
WORKDIR /fixture
COPY --from=build /build/target/classes ./classes
COPY --from=build /build/target/dependency ./lib
COPY --from=build /build/test-keys ./test-keys
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=50", "-cp", "classes:lib/*", "fixture.Fixture"]
