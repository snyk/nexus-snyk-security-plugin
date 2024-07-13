package io.snyk.plugins.nexus.capability;

public enum SnykSecurityCapabilityKey {
  API_URL("snyk.api.url", "https://api.snyk.io/v1/"),
  API_TOKEN("snyk.api.token", ""),
  API_TRUST_ALL_CERTIFICATES("snyk.api.trust.all.certificates", "false"),
  ORGANIZATION_ID("snyk.organization.id", ""),
  VULNERABILITY_THRESHOLD("snyk.scanner.vulnerability.threshold", "low"),
  LICENSE_THRESHOLD("snyk.scanner.license.threshold", "low"),
  PROXY_HOST("snyk.proxy.host", ""),
  PROXY_PORT("snyk.proxy.port", ""),
  PROXY_USER("snyk.proxy.user", ""),
  PROXY_PASSWORD("snyk.proxy.password", "");

  private final String propertyKey;
  private final String defaultValue;

  SnykSecurityCapabilityKey(String propertyKey, String defaultValue) {
    this.propertyKey = propertyKey;
    this.defaultValue = defaultValue;
  }

  public String propertyKey() {
    return propertyKey;
  }

  public String defaultValue() {
    return defaultValue;
  }
}
