package io.snyk.plugins.nexus.capability;

import javax.inject.Inject;
import javax.inject.Named;
import java.util.Map;

import org.sonatype.nexus.capability.CapabilitySupport;

import static io.snyk.plugins.nexus.capability.SnykSecurityCapabilityKey.API_TOKEN;

@Named(SnykSecurityCapabilityDescriptor.CAPABILITY_ID)
public class SnykSecurityCapability extends CapabilitySupport<SnykSecurityCapabilityConfiguration> {
  
  @Inject
  public SnykSecurityCapability() {
  }

  @Override
  protected SnykSecurityCapabilityConfiguration createConfig(Map<String, String> properties) {
    return new SnykSecurityCapabilityConfiguration(properties);
  }

  @Override
  public boolean isPasswordProperty(String propertyName) {
    return API_TOKEN.propertyKey().equals(propertyName);
  }

  @Override
  protected void configure(SnykSecurityCapabilityConfiguration config) throws Exception {
    super.configure(config);
  }
}
