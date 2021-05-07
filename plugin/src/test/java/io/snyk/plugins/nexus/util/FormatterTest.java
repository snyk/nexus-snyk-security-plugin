package io.snyk.plugins.nexus.util;

import io.snyk.plugins.nexus.model.ScanResult;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

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

}
