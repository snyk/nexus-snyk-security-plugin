module.exports = {
  defaultCommandTimeout: 10000,
  e2e: {
    supportFile: './cypress/support/e2e.js',
    setupNodeEvents(on, config) {
      return require('./cypress/plugins/index.js')(on, config);
    },
  },
};
