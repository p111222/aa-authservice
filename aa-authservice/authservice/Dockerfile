FROM maven:3.8.4-openjdk-17 AS build

# Set the working directory inside the container
WORKDIR /app

# Copy the pom.xml file and download dependencies (this step is cached if no changes in pom.xml)
COPY pom.xml .

# Download project dependencies
RUN mvn dependency:go-offline

# Copy the source code into the container
COPY src ./src

# Build the Spring Boot app using Maven
RUN mvn clean package -DskipTests

# Step 2: Use a lightweight JDK image to run the application
FROM openjdk:17-jdk-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the packaged jar from the build stage
COPY --from=build /app/target/*.jar app.jar

# Expose the port that your Spring Boot application will run on
EXPOSE 8080

# Command to run the Spring Boot app
ENTRYPOINT ["java", "-jar", "app.jar"]