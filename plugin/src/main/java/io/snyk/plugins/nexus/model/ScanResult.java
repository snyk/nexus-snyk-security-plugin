package io.snyk.plugins.nexus.model;

public final class ScanResult {
  public long highVulnerabilityIssueCount = 0;
  public long mediumVulnerabilityIssueCount = 0;
  public long lowVulnerabilityIssueCount = 0;
  public long highLicenseIssueCount = 0;
  public long mediumLicenseIssueCount = 0;
  public long lowLicenseIssueCount = 0;
}
