Cypress.Commands.overwrite('click', (originalFn, ...args) => {
  const origVal = originalFn(...args);

  return new Promise((resolve) => {
    setTimeout(() => {
      resolve(origVal);
    }, 500);
  });
});
