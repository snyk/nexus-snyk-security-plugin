package io.snyk.plugins.nexus.util;

import io.snyk.plugins.nexus.model.ScanResult;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FormatterTest {

  @Test
  void enrichScanResultWithVulnerabilityIssues_null() {
    // given
    ScanResult scanResult = new ScanResult();

    // when
    Formatter.enrichScanResultWithVulnerabilityIssues(scanResult, null);

    // then
    Assertions.assertAll(
      () -> {
        Assertions.assertEquals(0, scanResult.criticalVulnerabilityIssueCount);
        Assertions.assertEquals(0, scanResult.highVulnerabilityIssueCount);
        Assertions.assertEquals(0, scanResult.mediumVulnerabilityIssueCount);
        Assertions.assertEquals(0, scanResult.lowVulnerabilityIssueCount);
      });
  }

  @Test
  void enrichScanResultWithVulnerabilityIssues_empty() {
    // given
    ScanResult scanResult = new ScanResult();

    // when
    Formatter.enrichScanResultWithVulnerabilityIssues(scanResult, "");

    // then
    Assertions.assertAll(
      () -> {
        Assertions.assertEquals(0, scanResult.criticalVulnerabilityIssueCount);
        Assertions.assertEquals(0, scanResult.highVulnerabilityIssueCount);
        Assertions.assertEquals(0, scanResult.mediumVulnerabilityIssueCount);
        Assertions.assertEquals(0, scanResult.lowVulnerabilityIssueCount);
      });
  }

  @Test
  void enrichScanResultWithVulnerabilityIssues_WithCritical() {
    // given
    ScanResult scanResult = new ScanResult();

    // when
    Formatter.enrichScanResultWithVulnerabilityIssues(scanResult, "5 critical, 3 high, 14 medium, 2 low");

    // then
    Assertions.assertAll(
      () -> {
        Assertions.assertEquals(5, scanResult.criticalVulnerabilityIssueCount);
        Assertions.assertEquals(3, scanResult.highVulnerabilityIssueCount);
        Assertions.assertEquals(14, scanResult.mediumVulnerabilityIssueCount);
        Assertions.assertEquals(2, scanResult.lowVulnerabilityIssueCount);
      });
  }

  @Test
  void enrichScanResultWithVulnerabilityIssues() {
    // given
    ScanResult scanResult = new ScanResult();

    // when
    Formatter.enrichScanResultWithVulnerabilityIssues(scanResult, "9 high, 5 medium, 8 low");

    // then
    Assertions.assertAll(
      () -> {
        Assertions.assertEquals(0, scanResult.criticalVulnerabilityIssueCount);
        Assertions.assertEquals(9, scanResult.highVulnerabilityIssueCount);
        Assertions.assertEquals(5, scanResult.mediumVulnerabilityIssueCount);
        Assertions.assertEquals(8, scanResult.lowVulnerabilityIssueCount);
      });
  }

  @Test
  void enrichScanResultWithVulnerabilityIssuesThrowsIfInvalidFormat() {
    ScanResult scanResult = new ScanResult();
    RuntimeException e = assertThrows(RuntimeException.class, () -> Formatter.enrichScanResultWithVulnerabilityIssues(scanResult, "10 super, 15 elite, 20 fantastic"));
    assertEquals(e.getMessage(), "Invalid format for vulnerability issues: 10 super, 15 elite, 20 fantastic");
  }

  @Test
  void enrichScanResultWithVulnerabilityIssuesThrowsIfInvalidValues() {
    ScanResult scanResult = new ScanResult();
    RuntimeException e = assertThrows(RuntimeException.class, () -> Formatter.enrichScanResultWithVulnerabilityIssues(scanResult, "a critical, b high, c medium, d low"));
    assertEquals(e.getMessage(), "Invalid format for vulnerability issues: a critical, b high, c medium, d low");
  }

  @Test
  void enrichScanResultWithLicenseIssues_null() {
    // given
    ScanResult scanResult = new ScanResult();

    // when
    Formatter.enrichScanResultWithLicenseIssues(scanResult, null);

    // then
    Assertions.assertAll(
      () -> {
        Assertions.assertEquals(0, scanResult.highLicenseIssueCount);
        Assertions.assertEquals(0, scanResult.mediumLicenseIssueCount);
        Assertions.assertEquals(0, scanResult.lowLicenseIssueCount);
      });
  }

  @Test
  void enrichScanResultWithLicenseIssues_empty() {
    // given
    ScanResult scanResult = new ScanResult();

    // when
    Formatter.enrichScanResultWithLicenseIssues(scanResult, "");

    // then
    Assertions.assertAll(
      () -> {
        Assertions.assertEquals(0, scanResult.highLicenseIssueCount);
        Assertions.assertEquals(0, scanResult.mediumLicenseIssueCount);
        Assertions.assertEquals(0, scanResult.lowLicenseIssueCount);
      });
  }
   @Test
  void enrichScanResultWithLicenseIssues() {
    // given
    ScanResult scanResult = new ScanResult();

    // when
    Formatter.enrichScanResultWithLicenseIssues(scanResult, "10 high, 0 medium, 25 low");

    // then
    Assertions.assertAll(
      () -> {
        Assertions.assertEquals(10, scanResult.highLicenseIssueCount);
        Assertions.assertEquals(0, scanResult.mediumLicenseIssueCount);
        Assertions.assertEquals(25, scanResult.lowLicenseIssueCount);
      });
  }

  @Test
  void enrichScanResultWithLicenseIssuesWhenFormattedIssuesContainsCritical() {
    ScanResult scanResult = new ScanResult();

    // when
    Formatter.enrichScanResultWithLicenseIssues(scanResult, "6 critical, 10 high, 0 medium, 25 low");

    // then
    Assertions.assertAll(
      () -> {
        Assertions.assertEquals(10, scanResult.highLicenseIssueCount);
        Assertions.assertEquals(0, scanResult.mediumLicenseIssueCount);
        Assertions.assertEquals(25, scanResult.lowLicenseIssueCount);
      });
  }

  @Test
  void enrichScanResultWithLicenseIssuesThrowsIfInvalidFormat() {
    ScanResult scanResult = new ScanResult();
    RuntimeException e = assertThrows(RuntimeException.class, () -> Formatter.enrichScanResultWithLicenseIssues(scanResult, "10 super, 15 elite, 20 fantastic"));
    assertEquals(e.getMessage(), "Invalid format for license issues: 10 super, 15 elite, 20 fantastic");
  }

  @Test
  void enrichScanResultWithLicenseIssuesThrowsIfInvalidValues() {
    ScanResult scanResult = new ScanResult();
    RuntimeException e = assertThrows(RuntimeException.class, () -> Formatter.enrichScanResultWithLicenseIssues(scanResult, "x critical, y high, 0 medium, z low"));
    assertEquals(e.getMessage(), "Invalid format for license issues: x critical, y high, 0 medium, z low");
  }

}
