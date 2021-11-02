package io.snyk.plugins.nexus.util;

import io.snyk.plugins.nexus.model.ScanResult;
import io.snyk.sdk.model.Issue;
import io.snyk.sdk.model.Severity;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.snyk.sdk.util.Predicates.distinctByKey;

public final class Formatter {

  private static final Pattern ISSUES_WITH_CRITICAL_REGEX = Pattern.compile("(\\d+) critical, (\\d+) high, (\\d+) medium, (\\d+) low");
  private static final Pattern ISSUES_WITHOUT_CRITICAL_REGEX = Pattern.compile("(\\d+) high, (\\d+) medium, (\\d+) low");

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

    IssueCounts issueCounts = getIssueCountsFromFormattedString(formattedIssues)
      .orElseThrow(() -> new RuntimeException(String.format("Invalid format for vulnerability issues: %s", formattedIssues)));
    scanResult.criticalVulnerabilityIssueCount = issueCounts.critical.orElse(Long.valueOf(0));
    scanResult.highVulnerabilityIssueCount = issueCounts.high;
    scanResult.mediumVulnerabilityIssueCount = issueCounts.medium;
    scanResult.lowVulnerabilityIssueCount = issueCounts.low;
  }

  public static void enrichScanResultWithLicenseIssues(@Nonnull ScanResult scanResult, String formattedIssues) {
    if (formattedIssues == null || formattedIssues.isEmpty()) {
      scanResult.lowLicenseIssueCount = 0;
      scanResult.mediumLicenseIssueCount = 0;
      scanResult.highLicenseIssueCount = 0;
      return;
    }

    IssueCounts issueCounts = getIssueCountsFromFormattedString(formattedIssues)
      .orElseThrow(() -> new RuntimeException(String.format("Invalid format for license issues: %s", formattedIssues)));
    // regardless of if critical is present or not, we ignore it
    scanResult.highLicenseIssueCount = issueCounts.high;
    scanResult.mediumLicenseIssueCount = issueCounts.medium;
    scanResult.lowLicenseIssueCount = issueCounts.low;
  }

  public static Optional<IssueCounts> getIssueCountsFromFormattedString(String formattedIssues) {
    Matcher issuesWithCriticalMatch = ISSUES_WITH_CRITICAL_REGEX.matcher(formattedIssues);
    if (issuesWithCriticalMatch.matches()) {
      return Optional.of(new IssueCounts(
        issuesWithCriticalMatch.group(1),
        issuesWithCriticalMatch.group(2),
        issuesWithCriticalMatch.group(3),
        issuesWithCriticalMatch.group(4)
      ));
    }

    Matcher issuesWithoutCriticalMatch = ISSUES_WITHOUT_CRITICAL_REGEX.matcher(formattedIssues);
    if (issuesWithoutCriticalMatch.matches()) {
      return Optional.of(new IssueCounts(
        issuesWithoutCriticalMatch.group(1),
        issuesWithoutCriticalMatch.group(2),
        issuesWithoutCriticalMatch.group(3)
      ));
    }

    return Optional.empty();
  }
}

class IssueCounts {
  Optional<Long> critical = Optional.empty();
  long high = 0;
  long medium = 0;
  long low = 0;

  IssueCounts(String critical, String high, String medium, String low) {
    this.critical = Optional.of(Long.parseLong(critical));
    this.high = Long.parseLong(high);
    this.medium = Long.parseLong(medium);
    this.low = Long.parseLong(low);
  }

  IssueCounts(String high, String medium, String low) {
    this.high = Long.parseLong(high);
    this.medium = Long.parseLong(medium);
    this.low = Long.parseLong(low);
  }
}
