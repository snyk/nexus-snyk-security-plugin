module.exports = (on, config) => {
  config.env.nexusAdminPass = process.env.NEXUS_ADMIN_PASS;
  config.env.nexusPass = process.env.NEXUS_PASS;
  config.env.snykToken = process.env.TEST_SNYK_TOKEN;
  config.env.snykOrg = process.env.TEST_SNYK_ORG;
  return config;
}
