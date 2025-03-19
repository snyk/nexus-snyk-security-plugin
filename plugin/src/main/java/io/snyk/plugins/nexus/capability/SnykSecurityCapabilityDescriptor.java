package io.snyk.plugins.nexus.capability;

import javax.inject.Named;
import javax.inject.Singleton;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.sonatype.nexus.capability.CapabilityDescriptorSupport;
import org.sonatype.nexus.capability.CapabilityType;
import org.sonatype.nexus.capability.Tag;
import org.sonatype.nexus.capability.Taggable;
import org.sonatype.nexus.formfields.CheckboxFormField;
import org.sonatype.nexus.formfields.FormField;
import org.sonatype.nexus.formfields.StringTextFormField;
import org.sonatype.nexus.formfields.PasswordFormField;
import org.sonatype.nexus.common.upgrade.AvailabilityVersion;

import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.*;

@Singleton
@AvailabilityVersion(from = "1.0")
@Named(SnykSecurityCapabilityDescriptor.CAPABILITY_ID)
public class SnykSecurityCapabilityDescriptor extends CapabilityDescriptorSupport<SnykSecurityCapabilityConfiguration> implements Taggable {
  static final String CAPABILITY_ID = "snyk.security";
  private static final String CAPABILITY_NAME = "Snyk Security Configuration";
  private static final String CAPABILITY_DESCRIPTION = "Provides support to test artifacts against the Snyk vulnerability database";

  private final StringTextFormField fieldApiUrl;
  private final StringTextFormField fieldApiToken;
  private final CheckboxFormField fieldUseCustomSSLCertificate;
  private final StringTextFormField fieldOrganizationId;
  private final StringTextFormField fieldVulnerabilityThreshold;
  private final StringTextFormField fieldLicenseThreshold;
  private final StringTextFormField fieldProxyHost;
  private final StringTextFormField fieldProxyPort;
  private final StringTextFormField fieldProxyUser;
  private final PasswordFormField fieldProxyPassword;

  public SnykSecurityCapabilityDescriptor() {
    fieldApiUrl = new StringTextFormField(API_URL.propertyKey(), "Snyk API URL", "", FormField.MANDATORY).withInitialValue(API_URL.defaultValue());
    fieldApiToken = new StringTextFormField(API_TOKEN.propertyKey(), "Snyk API Token", "", FormField.MANDATORY).withInitialValue(API_TOKEN.defaultValue());
    fieldUseCustomSSLCertificate = new CheckboxFormField(API_TRUST_ALL_CERTIFICATES.propertyKey(), "Use custom SSL certificate", "", FormField.OPTIONAL).withInitialValue(false);
    fieldOrganizationId = new StringTextFormField(ORGANIZATION_ID.propertyKey(), "Snyk Organization ID", "", FormField.MANDATORY).withInitialValue(ORGANIZATION_ID.defaultValue());
    fieldVulnerabilityThreshold = new StringTextFormField(VULNERABILITY_THRESHOLD.propertyKey(), "Vulnerability Threshold", "", FormField.MANDATORY).withInitialValue(VULNERABILITY_THRESHOLD.defaultValue());
    fieldLicenseThreshold = new StringTextFormField(LICENSE_THRESHOLD.propertyKey(), "License Threshold", "", FormField.MANDATORY).withInitialValue(LICENSE_THRESHOLD.defaultValue());
    fieldProxyHost = new StringTextFormField(PROXY_HOST.propertyKey(), "Proxy host (optional)", "", FormField.OPTIONAL).withInitialValue(PROXY_HOST.defaultValue());
    fieldProxyPort = new StringTextFormField(PROXY_PORT.propertyKey(), "Proxy port (optional)", "", FormField.OPTIONAL).withInitialValue(PROXY_PORT.defaultValue());
    fieldProxyUser = new StringTextFormField(PROXY_USER.propertyKey(), "Proxy username (optional)", "", FormField.OPTIONAL).withInitialValue(PROXY_USER.defaultValue());
    fieldProxyPassword = new PasswordFormField(PROXY_PASSWORD.propertyKey(), "Proxy password (optional)", "", FormField.OPTIONAL).withInitialValue(PROXY_PASSWORD.defaultValue());
  }

  @Override
  public CapabilityType type() {
    return CapabilityType.capabilityType(CAPABILITY_ID);
  }

  @Override
  public String name() {
    return CAPABILITY_NAME;
  }

  @Override
  public String about() {
    return CAPABILITY_DESCRIPTION;
  }

  @Override
  public List<FormField> formFields() {
    return Arrays.asList(fieldApiUrl, fieldApiToken, fieldUseCustomSSLCertificate, fieldOrganizationId, fieldVulnerabilityThreshold, fieldLicenseThreshold, fieldProxyHost, fieldProxyPort, fieldProxyUser, fieldProxyPassword);
  }

  @Override
  protected SnykSecurityCapabilityConfiguration createConfig(Map<String, String> properties) {
    return new SnykSecurityCapabilityConfiguration(properties);
  }

  @Override
  public Set<Tag> getTags() {
    return Collections.singleton(Tag.categoryTag("Security"));
  }
}
