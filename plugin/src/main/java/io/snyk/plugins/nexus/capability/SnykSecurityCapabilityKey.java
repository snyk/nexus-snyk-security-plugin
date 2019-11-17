package io.snyk.plugins.nexus.capability;

public enum SnykSecurityCapabilityKey {
  API_URL("snyk.api.url"),
  API_TOKEN("snyk.api.token"),
  ORGANIZATION_ID("snyk.organization.id"),
  VULNERABILITY_THRESHOLD("snyk.scanner.vulnerability.threshold"),
  LICENSE_THRESHOLD("snyk.scanner.license.threshold"),
  ;

  private final String propertyKey;

  SnykSecurityCapabilityKey(String propertyKey) {
    this.propertyKey = propertyKey;
  }

  public String propertyKey() {
    return propertyKey;
  }
}
