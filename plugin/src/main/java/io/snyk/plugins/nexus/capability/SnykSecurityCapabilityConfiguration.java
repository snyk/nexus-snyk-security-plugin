package io.snyk.plugins.nexus.capability;

import java.util.Map;

import org.sonatype.nexus.capability.CapabilityConfigurationSupport;

import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.*;

public class SnykSecurityCapabilityConfiguration extends CapabilityConfigurationSupport {
  private String apiUrl;
  private String apiToken;
  private String organizationId;
  private String vulnerabilityThreshold;
  private String licenseThreshold;
  private String proxyHost;
  private String proxyPort;
  private String proxyUser;
  private String proxyPassword;

  SnykSecurityCapabilityConfiguration(Map<String, String> properties) {
    apiUrl = properties.getOrDefault(API_URL.propertyKey(), API_URL.defaultValue());
    apiToken = properties.get(API_TOKEN.propertyKey());
    organizationId = properties.get(ORGANIZATION_ID.propertyKey());
    vulnerabilityThreshold = properties.getOrDefault(VULNERABILITY_THRESHOLD.propertyKey(), VULNERABILITY_THRESHOLD.defaultValue());
    licenseThreshold = properties.getOrDefault(LICENSE_THRESHOLD.propertyKey(), LICENSE_THRESHOLD.defaultValue());
    proxyHost = properties.getOrDefault(PROXY_HOST.propertyKey(), PROXY_HOST.defaultValue());
    proxyPort = properties.getOrDefault(PROXY_PORT.propertyKey(), PROXY_PORT.defaultValue());
    proxyUser = properties.getOrDefault(PROXY_USER.propertyKey(), PROXY_USER.defaultValue());
    proxyPassword = properties.getOrDefault(PROXY_PASSWORD.propertyKey(), PROXY_PASSWORD.defaultValue());

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

  public String getProxyHost() {
    return proxyHost;
  }
  public String getProxyPort() {
    return proxyPort;
  }
  public String getProxyUser() {
    return proxyUser;
  }
  public String getProxyPassword() {
    return proxyPassword;
  }
}
