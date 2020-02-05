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
import org.sonatype.nexus.transaction.Transactional;

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
    if (snykClient == null) {
      snykClient = configurationHelper.getSnykClient();
    }
    if (configuration == null) {
      configuration = configurationHelper.getConfiguration();
    }

    String vulnerabilityThreshold = configuration.getVulnerabilityThreshold();
    if ("none".equals(vulnerabilityThreshold)) {
      LOG.warn("No scan needed");
      return;
    }

    LOG.debug("Scanning component: {}", context.getRequest().getPath());

    TestResult testResult = null;
    MavenPath.Coordinates coordinates = null;

    Object mavenPathAttribute = context.getAttributes().get(MavenPath.class.getName());
    if (mavenPathAttribute instanceof MavenPath) {
      MavenPath mavenPath = (MavenPath) mavenPathAttribute;
      MavenPath parsedMavenPath = mavenPathParser.parsePath(mavenPath.getPath());

      coordinates = parsedMavenPath.getCoordinates();
      if (coordinates == null) {
        LOG.warn("Coordinates are null for {}", parsedMavenPath);
      } else {
        if ("jar".equals(coordinates.getExtension())) {
          testResult = mavenScanner.scan(coordinates, snykClient, configuration.getOrganizationId());
        } else {
          LOG.warn("Extension is not supported: {}", mavenPath.getPath());
        }
      }
    }

    if (testResult == null) {
      LOG.warn("We could not scan component");
      return;
    }

    LOG.info("Vulnerabilities all: {}", testResult.issues.vulnerabilities.size());
    LOG.info("Licenses all: {}", testResult.issues.licenses.size());

    LOG.warn("Adding metadata here...");
    addMetadata(testResult, coordinates, context);

    LOG.warn("Validate findings...");
    if (!testResult.issues.vulnerabilities.isEmpty()) {
      throw new RuntimeException(format("Asset '%s' has vulnerabilities: %s", context.getRequest().getPath(), getIssuesAsFormattedString(testResult.issues.vulnerabilities)));
    }
  }

  private void addMetadata(TestResult testResult, MavenPath.Coordinates coordinates, @Nonnull Context context) {
    if (testResult == null) {
      return;
    }

    HashMap<String, String> filter = new HashMap<>(1);
    filter.put("version", coordinates.getVersion());
    List<Component> components = componentStore.getAllMatchingComponents(context.getRepository(), coordinates.getGroupId(), coordinates.getArtifactId(), filter);
    Component component = components.get(0);

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

  private String getIssuesAsFormattedString(@Nonnull List<? extends Issue> issues) {
    long countHighSeverities = issues.stream().filter(issue -> issue.severity == Severity.HIGH).count();
    long countMediumSeverities = issues.stream().filter(issue -> issue.severity == Severity.MEDIUM).count();
    long countLowSeverities = issues.stream().filter(issue -> issue.severity == Severity.LOW).count();

    return format("%d high, %d medium, %d low", countHighSeverities, countMediumSeverities, countLowSeverities);
  }
}
