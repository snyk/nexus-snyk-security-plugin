package io.snyk.plugins.nexus.util;

import javax.annotation.Nonnull;

import java.util.List;

import io.snyk.plugins.nexus.model.ScanResult;
import io.snyk.sdk.model.Issue;
import io.snyk.sdk.model.Severity;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.snyk.sdk.util.Predicates.distinctByKey;

public final class Formatter {

  private static final Pattern LICENSE_ISSUES_WITH_CRITICAL_REGEX = Pattern.compile("(\\d+) critical, (\\d+) high, (\\d+) medium, (\\d+) low");
  private static final Pattern LICENSE_ISSUES_WITHOUT_CRITICAL_REGEX = Pattern.compile("(\\d+) high, (\\d+) medium, (\\d+) low");

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

    Matcher licenseIssuesWithCriticalMatch = LICENSE_ISSUES_WITH_CRITICAL_REGEX.matcher(formattedIssues);
    if (licenseIssuesWithCriticalMatch.find()) {
      String high = licenseIssuesWithCriticalMatch.group(2); // group(1) is critical which we don't use for licenses
      String medium = licenseIssuesWithCriticalMatch.group(3);
      String low = licenseIssuesWithCriticalMatch.group(4);

      scanResult.highLicenseIssueCount = Long.parseLong(high);
      scanResult.mediumLicenseIssueCount = Long.parseLong(medium);
      scanResult.lowLicenseIssueCount = Long.parseLong(low);

      return;
    }

    Matcher licenseIssuesWithoutCriticalMatch = LICENSE_ISSUES_WITHOUT_CRITICAL_REGEX.matcher(formattedIssues);
    if (licenseIssuesWithoutCriticalMatch.matches()) {
      String high = licenseIssuesWithoutCriticalMatch.group(1);
      String medium = licenseIssuesWithoutCriticalMatch.group(2);
      String low = licenseIssuesWithoutCriticalMatch.group(3);

      scanResult.highLicenseIssueCount = Long.parseLong(high);
      scanResult.mediumLicenseIssueCount = Long.parseLong(medium);
      scanResult.lowLicenseIssueCount = Long.parseLong(low);

      return;
    }

    throw new RuntimeException(String.format("Invalid format for license issues: %s", formattedIssues));
  }
}
