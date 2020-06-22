package io.snyk.plugins.nexus.scanner;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.HashMap;
import java.util.List;

import io.snyk.plugins.nexus.capability.SnykSecurityCapabilityConfiguration;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.Issue;
import io.snyk.sdk.model.Severity;
import io.snyk.sdk.model.TestResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.common.collect.NestedAttributesMap;
import org.sonatype.nexus.repository.browse.BrowseResult;
import org.sonatype.nexus.repository.browse.BrowseService;
import org.sonatype.nexus.repository.maven.MavenPath;
import org.sonatype.nexus.repository.maven.MavenPathParser;
import org.sonatype.nexus.repository.storage.Asset;
import org.sonatype.nexus.repository.storage.AssetStore;
import org.sonatype.nexus.repository.storage.Component;
import org.sonatype.nexus.repository.storage.ComponentStore;
import org.sonatype.nexus.repository.view.Context;

import static java.lang.String.format;

@Named
@Singleton
public class ScannerModule {
  private static final Logger LOG = LoggerFactory.getLogger(ScannerModule.class);

  @Inject
  private ConfigurationHelper configurationHelper;
  @Inject
  private MavenPathParser mavenPathParser;
  @Inject
  private MavenScanner mavenScanner;
  @Inject
  private AssetStore assetStore;
  @Inject
  private ComponentStore componentStore;
  @Inject
  private BrowseService browseService;

  private SnykClient snykClient;
  private SnykSecurityCapabilityConfiguration configuration;

  void scanComponent(@Nonnull Context context) {
    TestResult testResult = null;
    try {
      initializeModuleIfNeeded();

      LOG.debug("Scanning component: {}", context.getRequest().getPath());
      MavenPath.Coordinates coordinates = null;

      Object mavenPathAttribute = context.getAttributes().get(MavenPath.class.getName());
      if (mavenPathAttribute instanceof MavenPath) {
        //TODO(pavel): move logic to maven subpackage
        MavenPath mavenPath = (MavenPath) mavenPathAttribute;
        MavenPath parsedMavenPath = mavenPathParser.parsePath(mavenPath.getPath());

        coordinates = parsedMavenPath.getCoordinates();
        if (coordinates == null) {
          LOG.warn("Coordinates are null for {}", parsedMavenPath);
        } else {
          if ("jar".equals(coordinates.getExtension())) {
            testResult = mavenScanner.scan(coordinates, snykClient, configuration.getOrganizationId());
          } else {
            LOG.debug("Extension is not supported: {}", mavenPath.getPath());
          }
        }
      }

      if (testResult == null) {
        LOG.warn("Component could not be scanned, check the logs scanner modules: {}", context.getRequest().getPath());
        return;
      }

      updateAssetAttributes(testResult, coordinates, context);
    } catch (Exception ex) {
      LOG.error("Could not scan component", ex);
    }
    validateVulnerabilityIssues(testResult, context.getRequest().getPath());
    validateLicenseIssues(testResult, context.getRequest().getPath());
  }

  private void initializeModuleIfNeeded() {
    if (snykClient == null) {
      snykClient = configurationHelper.getSnykClient();
    }
    if (configuration == null) {
      configuration = configurationHelper.getConfiguration();
    }
  }

  private void updateAssetAttributes(@Nonnull TestResult testResult, MavenPath.Coordinates coordinates, @Nonnull Context context) {
    HashMap<String, String> filter = new HashMap<>(1);
    filter.put("version", coordinates.getVersion());
    List<Component> matchingComponents = componentStore.getAllMatchingComponents(context.getRepository(), coordinates.getGroupId(), coordinates.getArtifactId(), filter);
    Component component = (matchingComponents != null && !matchingComponents.isEmpty()) ? matchingComponents.get(0) : null;
    BrowseResult<Asset> assetBrowseResult = browseService.browseComponentAssets(context.getRepository(), component);
    Asset asset = assetBrowseResult.getResults().stream()
                                   .filter(e -> "application/java-archive".equals(e.contentType()))
                                   .findFirst().orElse(null);
    if (asset == null) {
      return;
    }

    NestedAttributesMap snykSecurityMap = asset.attributes().child("Snyk Security");
    snykSecurityMap.clear();

    snykSecurityMap.set("issues_vulnerabilities", getIssuesAsFormattedString(testResult.issues.vulnerabilities));
    snykSecurityMap.set("issues_licenses", getIssuesAsFormattedString(testResult.issues.licenses));
    StringBuilder snykIssueUrl = new StringBuilder("https://snyk.io/vuln/");
    snykIssueUrl.append("maven:")
                .append(coordinates.getGroupId()).append("%3A")
                .append(coordinates.getArtifactId()).append("@")
                .append(coordinates.getVersion());
    snykSecurityMap.set("issues_url", snykIssueUrl.toString());

    assetStore.save(asset);
  }

  private Long countUniqueIssuesBySeverity(List<? extends Issue> issues, Severity severity) {
    return issues.stream().filter(issue -> issue.severity == severity).map(issue -> issue.id).distinct().count();
  }

  private String getIssuesAsFormattedString(@Nonnull List<? extends Issue> issues) {
    long countHighSeverities = countUniqueIssuesBySeverity(issues, Severity.HIGH);
    long countMediumSeverities = countUniqueIssuesBySeverity(issues, Severity.MEDIUM);
    long countLowSeverities = countUniqueIssuesBySeverity(issues, Severity.LOW);

    return format("%d high, %d medium, %d low", countHighSeverities, countMediumSeverities, countLowSeverities);
  }

  private void validateVulnerabilityIssues(TestResult testResult, @Nonnull String path) {
    if (testResult == null) {
      LOG.warn("Component could not be scanned, check the logs scanner modules: {}", path);
      return;
    }

    String vulnerabilityThreshold = configuration.getVulnerabilityThreshold();

    if ("none".equals(vulnerabilityThreshold)) {
      LOG.info("Property 'Vulnerability Threshold' is none, so we allow to download artifact.");
      return;
    }

    if ("low".equals(vulnerabilityThreshold)) {
      if (!testResult.issues.vulnerabilities.isEmpty()) {
        throw new RuntimeException(format("Artifact '%s' has vulnerability issues: '%s'", path, getIssuesAsFormattedString(testResult.issues.vulnerabilities)));
      }
    } else if ("medium".equals(vulnerabilityThreshold)) {
      long count = testResult.issues.vulnerabilities.stream()
                                                    .filter(vulnerability -> vulnerability.severity == Severity.MEDIUM || vulnerability.severity == Severity.HIGH)
                                                    .count();
      if (count > 0) {
        throw new RuntimeException(format("Artifact '%s' has vulnerability issues: '%s'", path, getIssuesAsFormattedString(testResult.issues.vulnerabilities)));
      }
    } else if ("high".equals(vulnerabilityThreshold)) {
      long count = testResult.issues.vulnerabilities.stream()
                                                    .filter(vulnerability -> vulnerability.severity == Severity.HIGH)
                                                    .count();
      if (count > 0) {
        throw new RuntimeException(format("Artifact '%s' has vulnerability issues: '%s'", path, getIssuesAsFormattedString(testResult.issues.vulnerabilities)));
      }
    }
  }

  private void validateLicenseIssues(TestResult testResult, @Nonnull String path) {
    if (testResult == null) {
      LOG.warn("Component could not be scanned, check the logs scanner modules: {}", path);
      return;
    }

    String licenseThreshold = configuration.getLicenseThreshold();

    if ("none".equals(licenseThreshold)) {
      LOG.info("Property 'License Threshold' is none, so we allow to download artifact.");
      return;
    }

    if ("low".equals(licenseThreshold)) {
      if (!testResult.issues.licenses.isEmpty()) {
        throw new RuntimeException(format("Artifact '%s' has license issues: '%s'", path, getIssuesAsFormattedString(testResult.issues.licenses)));
      }
    } else if ("medium".equals(licenseThreshold)) {
      long count = testResult.issues.licenses.stream()
                                             .filter(vulnerability -> vulnerability.severity == Severity.MEDIUM || vulnerability.severity == Severity.HIGH)
                                             .count();
      if (count > 0) {
        throw new RuntimeException(format("Artifact '%s' has license issues: '%s'", path, getIssuesAsFormattedString(testResult.issues.licenses)));
      }
    } else if ("high".equals(licenseThreshold)) {
      long count = testResult.issues.licenses.stream()
                                             .filter(vulnerability -> vulnerability.severity == Severity.HIGH)
                                             .count();
      if (count > 0) {
        throw new RuntimeException(format("Artifact '%s' has license issues: '%s'", path, getIssuesAsFormattedString(testResult.issues.licenses)));
      }
    }
  }
}
