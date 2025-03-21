# Nexus Repository Manager and Snyk Integration

## Introduction

[Nexus Repository Manager](https://www.sonatype.com/nexus/repository-oss) is a free, open-source artifact repository with universal format support. It allows you to proxy, collect, and manage your dependencies so that you are not constantly juggling a collection of JARs. It makes it easy to distribute your software by providing a single source of truth for all your components, binaries, and build artifacts.

## Setting up Nexus Repository Manager Locally

1. Install Docker on your machine if you haven't already. You can download it from [Docker's official website](https://www.docker.com/products/docker-desktop).

2. Pull the Nexus Docker image and run a container:

```bash
docker pull sonatype/nexus3
docker run -d -p 8081:8081 --name nexus sonatype/nexus3
```

3. Open your web browser and navigate to `http://localhost:8081`. You should see the Nexus Repository Manager interface.

## Using Nexus Repository Manager

1. The default username is `admin`. The password is stored in a file inside the Docker container. You can retrieve it by running:

```bash
docker exec -it nexus cat /nexus-data/admin.password
```

2. Log in to Nexus using the `admin` username and the password you retrieved.

3. You will be prompted to change your password and set up email.

## Setting up a Maven Development Environment

1. Pull the Maven Docker image:

```bash
docker pull maven:3.9.9-eclipse-temurin-17
```

2. Run a Maven container and mount the project:

```bash
docker run -it --name maven maven:3.9.9-eclipse-temurin-17 -v /path/to/nexus-snyk-security-plugin:/usr/src/nexus-snyk-security-plugin -w /usr/src/nexus-snyk-security-plugin bash
```

3. Inside the container, you can use Maven commands to build your project.

## Installing the Snyk Plugin

1. Build the Snyk plugin with Maven:

```bash
mvn clean install -PbuildKar
```

2. This will create a `.kar` file in the `target` directory. Copy this file to the `deploy` directory inside the Nexus container:

```bash
docker cp target/nexus-snyk-security-plugin-bundle.kar nexus:/opt/sonatype/nexus/deploy/
```

3. Restart the Nexus container:

```bash
docker restart nexus
```

4. Log in to Nexus and navigate to `System -> Capabilities -> New`. Select "Snyk Security Configuration" from the "Capability Type" dropdown. Enter your Snyk token and organization ID.

## Testing the Snyk Plugin

1. Create a new proxy repository in Nexus. Set the remote storage to `https://repo1.maven.org/maven2/`.

2. Download a vulnerable artifact, such as `log4j-core-2.14.1.jar`, and upload it to the proxy repository.

3. Try to download the artifact from the repository. You can use the following command:

```bash
curl -O http://localhost:8081/repository/<your-repository-name>/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar
```

Replace `<your-repository-name>` with the name of your repository. If Snyk is working correctly, the download should be blocked and you should see a message indicating that the artifact contains vulnerabilities. If the download is successful, you will get a "200" code and the file will be in your current directory.

4. To confirm that Snyk is working, you can check the Nexus logs:

```bash
docker exec -it nexus cat /nexus-data/log/nexus.log | grep -i snyk
```

This command will display all the log lines related to Snyk. If Snyk is working properly, you should see log lines indicating that Snyk has been activated and is scanning artifacts.

5. To test the Snyk plugin, you can try to download a vulnerable artifact from the proxy repository you created. For example, you can use the following command to download the `log4j-core` artifact:

```bash
curl -O http://localhost:8081/repository/maven-proxy/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar
```

If Snyk is working correctly and the artifact is vulnerable, the download should be blocked and you should receive a HTTP 500 error. If the artifact is not vulnerable, the download will succeed and you will receive a HTTP 200 status code.

Remember, the goal of the Snyk plugin is to prevent the download of vulnerable artifacts. So, a blocked download is actually a sign that everything is working as expected!
