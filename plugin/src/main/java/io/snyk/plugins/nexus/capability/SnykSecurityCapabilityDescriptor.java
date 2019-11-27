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

import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.API_TOKEN;
import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.API_TRUST_ALL_CERTIFICATES;
import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.API_URL;
import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.LICENSE_THRESHOLD;
import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.ORGANIZATION_ID;
import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.VULNERABILITY_THRESHOLD;

@Singleton
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

  public SnykSecurityCapabilityDescriptor() {
    fieldApiUrl = new StringTextFormField(API_URL.propertyKey(), "Snyk API URL", "", FormField.MANDATORY).withInitialValue(API_URL.defaultValue());
    fieldApiToken = new StringTextFormField(API_TOKEN.propertyKey(), "Snyk API Token", "", FormField.MANDATORY).withInitialValue(API_TOKEN.defaultValue());
    fieldUseCustomSSLCertificate = new CheckboxFormField(API_TRUST_ALL_CERTIFICATES.propertyKey(), "Use custom SSL certificate", "", FormField.OPTIONAL).withInitialValue(false);
    fieldOrganizationId = new StringTextFormField(ORGANIZATION_ID.propertyKey(), "Snyk Organization ID", "", FormField.MANDATORY).withInitialValue(ORGANIZATION_ID.defaultValue());
    fieldVulnerabilityThreshold = new StringTextFormField(VULNERABILITY_THRESHOLD.propertyKey(), "Vulnerability Threshold", "", FormField.MANDATORY).withInitialValue(VULNERABILITY_THRESHOLD.defaultValue());
    fieldLicenseThreshold = new StringTextFormField(LICENSE_THRESHOLD.propertyKey(), "License Threshold", "", FormField.MANDATORY).withInitialValue(LICENSE_THRESHOLD.defaultValue());
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
    return Arrays.asList(fieldApiUrl, fieldApiToken, fieldUseCustomSSLCertificate, fieldOrganizationId, fieldVulnerabilityThreshold, fieldLicenseThreshold);
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
