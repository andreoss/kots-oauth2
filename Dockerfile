FROM eclipse-temurin:21-jre
WORKDIR /opt/oauth2
COPY modules/host/target/scala-2.13/oauth2-host.jar oauth2-host.jar
EXPOSE 8080
USER nobody
ENTRYPOINT ["java", "-jar", "oauth2-host.jar"]
