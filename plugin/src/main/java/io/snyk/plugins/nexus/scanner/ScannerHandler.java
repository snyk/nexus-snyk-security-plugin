package io.snyk.plugins.nexus.scanner;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import io.snyk.plugins.nexus.capability.SnykSecurityCapabilityConfiguration;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.Severity;
import io.snyk.sdk.model.TestResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.repository.Format;
import org.sonatype.nexus.repository.Repository;
import org.sonatype.nexus.repository.Type;
import org.sonatype.nexus.repository.storage.Asset;
import org.sonatype.nexus.repository.storage.AssetStore;
import org.sonatype.nexus.repository.types.ProxyType;
import org.sonatype.nexus.repository.view.Content;
import org.sonatype.nexus.repository.view.Context;
import org.sonatype.nexus.repository.view.Payload;
import org.sonatype.nexus.repository.view.Response;
import org.sonatype.nexus.repository.view.handlers.ContributedHandler;

import static io.snyk.sdk.util.Formatter.getIssuesAsFormattedString;
import static java.lang.String.format;

@Named
@Singleton
public class ScannerHandler implements ContributedHandler {
  private static final Logger LOG = LoggerFactory.getLogger(ScannerHandler.class);

  private final ConfigurationHelper configurationHelper;
  private final MavenScanner mavenScanner;
  private final NpmScanner npmScanner;

  private SnykClient snykClient;
  private SnykSecurityCapabilityConfiguration configuration;

  @Inject
  public ScannerHandler(final ConfigurationHelper configurationHelper,
                        final MavenScanner mavenScanner,
                        final NpmScanner npmScanner) {
    this.configurationHelper = configurationHelper;
    this.mavenScanner = mavenScanner;
    this.npmScanner = npmScanner;

    initializeModuleIfNeeded();
  }

  @Nonnull
  @Override
  public Response handle(@Nonnull Context context) throws Exception {
    Response response = context.proceed();
    Payload payload = response.getPayload();

    Repository repository = context.getRepository();
    if (!ProxyType.NAME.equals(repository.getType().getValue())) {
      LOG.warn("Only proxy repositories are supported: {} - {}", repository.getName(), repository.getType());
      return response;
    }

    TestResult testResult = null;
    String repositoryFormat = repository.getFormat().getValue();
    switch (repositoryFormat) {
      case "maven2": {
        testResult = mavenScanner.scan(context, payload, snykClient, configuration.getOrganizationId());
        break;
      }
      case "npm": {
        testResult = npmScanner.scan(context, payload, snykClient, configuration.getOrganizationId());
        break;
      }
      default:
        LOG.error("format {} is not supported", repositoryFormat);
        return response;
    }

    if (testResult == null) {
      return response;
    }

    validateVulnerabilityIssues(testResult, context.getRequest().getPath());
    validateLicenseIssues(testResult, context.getRequest().getPath());

    return response;
  }

  private void initializeModuleIfNeeded() {
    if (snykClient == null) {
      snykClient = configurationHelper.getSnykClient();
    }
    if (configuration == null) {
      configuration = configurationHelper.getConfiguration();
    }
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
