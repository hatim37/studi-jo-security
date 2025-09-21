# telechargement de maeven afin de construire la solution
FROM maven:3.9.7-eclipse-temurin-17 AS build
# créer un dossier
WORKDIR /app
#je copie le projet
COPY pom.xml .
#
RUN mvn -U -q -DskipTests dependency:go-offline
#
COPY src ./src
#
RUN mvn -U clean package -DskipTests

# Run
FROM eclipse-temurin:17-jre-jammy
#
WORKDIR /app
#
COPY --from=build /app/target/*.jar app.jar
#
EXPOSE 8091
# commande qui sera executé lors du lancement du container
ENTRYPOINT ["java","-jar","app.jar"]



