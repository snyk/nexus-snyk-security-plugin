package io.snyk.plugins.nexus.scanner;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import io.snyk.plugins.nexus.capability.SnykSecurityCapabilityConfiguration;
import io.snyk.plugins.nexus.capability.SnykSecurityCapabilityLocator;
import io.snyk.sdk.Snyk;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.config.SnykProxyConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.httpclient.config.ProxyConfiguration;
import org.sonatype.nexus.httpclient.config.ProxyServerConfiguration;
import org.sonatype.nexus.httpclient.config.UsernameAuthenticationConfiguration;

import java.util.Optional;

@Named
@Singleton
public class ConfigurationHelper {
  private static final Logger LOG = LoggerFactory.getLogger(ConfigurationHelper.class);

  @Inject
  private Provider<SnykSecurityCapabilityLocator> locatorProvider;

  @Nullable
  public SnykClient getSnykClient() {
    SnykSecurityCapabilityLocator locator = locatorProvider.get();

    if (locator == null) {
      LOG.warn("SnykClient cannot be built because SnykSecurityCapabilityLocator is null!");
      return null;
    } else {
      try {
        String proxyHost = locator.getSnykSecurityCapabilityConfiguration().getProxyHost();
        String proxyPort = locator.getSnykSecurityCapabilityConfiguration().getProxyPort();
        String proxyUser = locator.getSnykSecurityCapabilityConfiguration().getProxyUser();
        String proxyPassword = locator.getSnykSecurityCapabilityConfiguration().getProxyPassword();
        if(!proxyHost.isEmpty() && !proxyPort.isEmpty()) {
            SnykProxyConfig snykProxyConfig = new SnykProxyConfig(proxyHost, Integer.parseInt(proxyPort), proxyUser, proxyPassword);
            return Snyk.newBuilder(new Snyk.Config(locator.getSnykSecurityCapabilityConfiguration().getApiToken(), snykProxyConfig)).buildSync();
        }
        return Snyk.newBuilder(new Snyk.Config(locator.getSnykSecurityCapabilityConfiguration().getApiToken())).buildSync();
      } catch (Exception ex) {
        LOG.error("SnykClient could not be created", ex);
        return null;
      }
    }
  }

  @Nullable
  public SnykSecurityCapabilityConfiguration getConfiguration() {
    SnykSecurityCapabilityLocator locator = locatorProvider.get();

    if (locator == null) {
      return null;
    } else {
      return locator.getSnykSecurityCapabilityConfiguration();
    }
  }

  public boolean isCapabilityEnabled() {
    SnykSecurityCapabilityLocator locator = locatorProvider.get();

    if (locator == null) {
      return false;
    }

    return locator.isSnykSecurityCapabilityActive();
  }
}
