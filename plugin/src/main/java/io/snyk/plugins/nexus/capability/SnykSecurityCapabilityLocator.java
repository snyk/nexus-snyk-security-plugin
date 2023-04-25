package io.snyk.plugins.nexus.capability;

import javax.inject.Inject;
import javax.inject.Named;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.capability.Capability;
import org.sonatype.nexus.capability.CapabilityReference;
import org.sonatype.nexus.capability.CapabilityRegistry;

import java.util.Optional;
import java.util.Set;

@Named
public class SnykSecurityCapabilityLocator {
  private static final Logger LOG = LoggerFactory.getLogger(SnykSecurityCapabilityLocator.class);

  private final CapabilityRegistry capabilityRegistry;

  @Inject
  public SnykSecurityCapabilityLocator(final CapabilityRegistry capabilityRegistry) {
    this.capabilityRegistry = capabilityRegistry;
  }

  public boolean isSnykSecurityCapabilityActive() {
    LOG.debug("List all available Nexus capabilities");
    CapabilityReference reference = capabilityRegistry.getAll().stream()
                                                      .peek(e -> {
                                                        Capability capability = e.capability();
                                                        LOG.debug("  {}", capability);
                                                      })
                                                      .filter(e -> SnykSecurityCapability.class.getSimpleName().equals(e.capability().getClass().getSimpleName()))
                                                      .findFirst().orElse(null);
    if (reference == null) {
      LOG.debug("Snyk Security Configuration capability does not exist.");
      return false;
    }

    return reference.context().isActive();
  }

  public SnykSecurityCapabilityConfiguration getSnykSecurityCapabilityConfiguration() {
    CapabilityReference reference = capabilityRegistry.getAll().stream()
                                                      .filter(e -> SnykSecurityCapability.class.getSimpleName().equals(e.capability().getClass().getSimpleName()))
                                                      .findFirst().orElse(null);
    if (reference == null) {
      LOG.debug("Snyk Security Configuration capability not created.");
      return null;
    }

    SnykSecurityCapability snykSecurityCapability = reference.capabilityAs(SnykSecurityCapability.class);
    return snykSecurityCapability.getConfig();
  }
}
