package io.snyk.plugins.nexus.capability;

import javax.inject.Named;
import javax.inject.Singleton;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.sonatype.nexus.capability.CapabilityDescriptorSupport;
import org.sonatype.nexus.capability.CapabilityType;
import org.sonatype.nexus.formfields.FormField;
import org.sonatype.nexus.formfields.StringTextFormField;

import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.API_TOKEN;
import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.API_URL;
import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.LICENSE_THRESHOLD;
import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.ORGANIZATION_ID;
import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.VULNERABILITY_THRESHOLD;

@Singleton
@Named(SnykSecurityCapabilityDescriptor.CAPABILITY_ID)
public class SnykSecurityCapabilityDescriptor extends CapabilityDescriptorSupport<SnykSecurityCapabilityConfiguration> {
  static final String CAPABILITY_ID = "snyk.security";
  private static final String CAPABILITY_NAME = "Snyk Security Configuration";
  private static final String CAPABILITY_DESCRIPTION = "Provides support to test artifacts against the Snyk vulnerability database";

  private static final StringTextFormField API_URL_FIELD = new StringTextFormField(API_URL.propertyKey(), "Snyk API URL", "", FormField.MANDATORY);
  private static final StringTextFormField API_TOKEN_FIELD = new StringTextFormField(API_TOKEN.propertyKey(), "Snyk API Token", "", FormField.MANDATORY);
  private static final StringTextFormField ORGANIZATION_ID_FIELD = new StringTextFormField(ORGANIZATION_ID.propertyKey(), "Snyk Organization ID", "", FormField.MANDATORY);
  private static final StringTextFormField VULNERABILITY_THRESHOLD_FIELD = new StringTextFormField(VULNERABILITY_THRESHOLD.propertyKey(), "Vulnerability Threshold", "", FormField.MANDATORY);
  private static final StringTextFormField LICENSE_THRESHOLD_FIELD = new StringTextFormField(LICENSE_THRESHOLD.propertyKey(), "License Threshold", "", FormField.MANDATORY);

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
    List<FormField> fields = new ArrayList<>(5);
    fields.add(API_URL_FIELD);
    fields.add(API_TOKEN_FIELD);
    fields.add(ORGANIZATION_ID_FIELD);
    fields.add(VULNERABILITY_THRESHOLD_FIELD);
    fields.add(LICENSE_THRESHOLD_FIELD);
    return fields;
  }

  @Override
  protected SnykSecurityCapabilityConfiguration createConfig(Map<String, String> properties) {
    return new SnykSecurityCapabilityConfiguration(properties);
  }
}
