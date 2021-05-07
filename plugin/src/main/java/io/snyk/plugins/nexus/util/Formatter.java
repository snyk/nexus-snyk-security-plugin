package io.snyk.plugins.nexus.util;

import javax.annotation.Nonnull;

import java.util.List;

import io.snyk.plugins.nexus.model.ScanResult;
import io.snyk.sdk.model.Issue;
import io.snyk.sdk.model.Severity;

import static io.snyk.sdk.util.Predicates.distinctByKey;

public final class Formatter {
  private Formatter() {
  }

  public static long getIssuesCountBySeverity(@Nonnull List<? extends Issue> issues, @Nonnull Severity severity) {
    return issues.stream()
                 .filter(issue -> issue.severity == severity)
                 .filter(distinctByKey(issue -> issue.id))
                 .count();
  }

  public static String getVulnerabilityIssuesAsFormattedString(@Nonnull ScanResult scanResult) {
    return String.format("%d critical, %d high, %d medium, %d low", scanResult.criticalVulnerabilityIssueCount, scanResult.highVulnerabilityIssueCount, scanResult.mediumVulnerabilityIssueCount, scanResult.lowVulnerabilityIssueCount);
  }

  public static String getLicenseIssuesAsFormattedString(@Nonnull ScanResult scanResult) {
    return String.format("%d high, %d medium, %d low", scanResult.highLicenseIssueCount, scanResult.mediumLicenseIssueCount, scanResult.lowLicenseIssueCount);
  }

  public static void enrichScanResultWithVulnerabilityIssues(@Nonnull ScanResult scanResult, String formattedIssues) {
    if (formattedIssues == null || formattedIssues.isEmpty()) {
      scanResult.lowVulnerabilityIssueCount = 0;
      scanResult.mediumVulnerabilityIssueCount = 0;
      scanResult.highVulnerabilityIssueCount = 0;
      scanResult.criticalVulnerabilityIssueCount = 0;
      return;
    }

    String[] parts = formattedIssues.split(", ");

    int i = 0;
    if (parts.length == 4) {
      String critical = parts[i].replace(" critical", "");
      scanResult.criticalVulnerabilityIssueCount = Long.parseLong(critical);
      i++;
    }
    String high = parts[i].replace(" high", "");
    scanResult.highVulnerabilityIssueCount = Long.parseLong(high);
    i++;

    String medium = parts[i].replace(" medium", "");
    scanResult.mediumVulnerabilityIssueCount = Long.parseLong(medium);
    i++;

    String low = parts[i].replace(" low", "");
    scanResult.lowVulnerabilityIssueCount = Long.parseLong(low);
  }

  public static void enrichScanResultWithLicenseIssues(@Nonnull ScanResult scanResult, String formattedIssues) {
    if (formattedIssues == null || formattedIssues.isEmpty()) {
      scanResult.lowLicenseIssueCount = 0;
      scanResult.mediumLicenseIssueCount = 0;
      scanResult.highLicenseIssueCount = 0;
      return;
    }

    String[] parts = formattedIssues.split(", ");

    String high = parts[0].replace(" high", "");
    scanResult.highLicenseIssueCount = Long.parseLong(high);

    String medium = parts[1].replace(" medium", "");
    scanResult.mediumLicenseIssueCount = Long.parseLong(medium);

    String low = parts[2].replace(" low", "");
    scanResult.lowLicenseIssueCount = Long.parseLong(low);
  }
}
