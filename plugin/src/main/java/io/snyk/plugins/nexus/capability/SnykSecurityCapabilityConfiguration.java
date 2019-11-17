package io.snyk.plugins.nexus.capability;

import java.util.Map;

import org.sonatype.nexus.capability.CapabilityConfigurationSupport;

import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.API_TOKEN;
import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.API_URL;
import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.LICENSE_THRESHOLD;
import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.ORGANIZATION_ID;
import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.VULNERABILITY_THRESHOLD;

public class SnykSecurityCapabilityConfiguration extends CapabilityConfigurationSupport {
  private String apiUrl;
  private String apiToken;
  private String organizationId;
  private String vulnerabilityThreshold;
  private String licenseThreshold;

  public SnykSecurityCapabilityConfiguration(Map<String, String> properties) {
    apiUrl = properties.getOrDefault(API_URL.propertyKey(), "https://snyk.io/api/v1/");
    apiToken = properties.get(API_TOKEN.propertyKey());
    organizationId = properties.get(ORGANIZATION_ID.propertyKey());
    vulnerabilityThreshold = properties.getOrDefault(VULNERABILITY_THRESHOLD.propertyKey(), "low");
    licenseThreshold = properties.getOrDefault(LICENSE_THRESHOLD.propertyKey(), "low");

  }

  public String getApiUrl() {
    return apiUrl;
  }

  public String getApiToken() {
    return apiToken;
  }

  public String getOrganizationId() {
    return organizationId;
  }

  public String getVulnerabilityThreshold() {
    return vulnerabilityThreshold;
  }

  public String getLicenseThreshold() {
    return licenseThreshold;
  }
}
