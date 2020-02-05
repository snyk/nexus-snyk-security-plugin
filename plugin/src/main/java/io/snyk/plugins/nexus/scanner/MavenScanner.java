package io.snyk.plugins.nexus.scanner;

import javax.inject.Named;
import javax.inject.Singleton;
import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.TestResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.repository.maven.MavenPath;
import retrofit2.Response;

@Named
@Singleton
public class MavenScanner {
  private static final Logger LOG = LoggerFactory.getLogger(MavenScanner.class);

  TestResult scan(MavenPath.Coordinates mavenCoordinates, SnykClient snykClient, String organizationId) {
    TestResult testResult = null;
    try {
      Response<TestResult> response = snykClient.testMaven(mavenCoordinates.getGroupId(),
                                                           mavenCoordinates.getArtifactId(),
                                                           mavenCoordinates.getVersion(),
                                                           organizationId,
                                                           null).execute();
      if (response.isSuccessful() && response.body() != null) {
        testResult = response.body();
        String responseAsText = new ObjectMapper().writeValueAsString(response.body());
        LOG.warn("testMaven response: {}", responseAsText);
      }
    } catch (IOException ex) {
      LOG.error("Could not test maven artifact: {}", mavenCoordinates, ex);

    }

    return testResult;
  }
}
