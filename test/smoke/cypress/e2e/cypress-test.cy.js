describe('test', () => {
  it('log in, update password, and add Snyk plugin (Capability)', () => {
    // Ignore Javascript errors in the Nexus UI
    Cypress.on('uncaught:exception', (err, runnable) => {
      return false;
    });

    cy.visit('http://localhost:8081');
    cy.get('a[data-qtip="Sign in"]').should('be.visible').click();
    cy.get('.x-title-text').should('contain', 'Sign In').should('be.visible');

    // Fill in credentials
    cy.get('input[name="username"]').type('admin');
    cy.get('input[name="password"]').type(Cypress.env('nexusAdminPass'));
    cy.get('div[role="dialog"] a')
      .should('be.visible')
      .contains('Sign in')
      .click();
    cy.contains('User signed in').should('be.visible');

    cy.contains(
      'This wizard will help you complete required setup tasks.',
    ).should('be.visible');

    // Go through the mandatory wizard to set a new password
    cy.get('body').then(($body) => {
      if ($body.find('div[role="dialog"]').length) {
        cy.log('found the wizard');

        cy.get('div[role="dialog"]').then(($dialog) => {
          cy.log('in the diaglog callback');
          if ($dialog.find('a').length) {
            cy.log('found the Next button');
            cy.wrap($dialog).should('be.visible').contains('Next').click();
            cy.log('clicked the Next button');

            // Set new password
            cy.get('div[role="presentation"]').then(($presentation) => {
              cy.log('in the password page callback');
              if ($presentation.find('input[type="password"]').length) {
                cy.log('found the password text boxes');
                cy.wrap($presentation)
                  .get('input[type="password"]')
                  .each(($password) => {
                    cy.wrap($password).type(Cypress.env('nexusPass'));
                  });
                cy.log('set the passwords');

                cy.contains(
                  'div[role="dialog"] a[role="button"]:visible',
                  'Next',
                ).click();
                cy.log('clicked the Next button');
              } else {
                cy.log('no password text boxes');
              }
            });

            // Configure Anonymous access
            cy.contains(
              'div[role="presentation"] a[role="button"]:visible',
              'Next',
            ).click();
            cy.log('clicked the Next button');

            // Finish
            cy.contains(
              'div[role="dialog"] a[role="button"]:visible',
              'Finish',
            ).click();
          } else {
            cy.log('could not find the Next button');
          }
        });
      } else {
        cy.log('could not find the wizard');
      }
    });

    // dismiss the data collection banner
    cy.get("#panel-1154-innerCt").should("exist").then((button) => {
      if (button.length > 0) {
        cy.wrap(button).click();
      } else {
        cy.log("could not find the dismiss data collection button");
      }
    })

    // Add Capability
    cy.get('a[data-qtip="Server administration and configuration"]').click();
    cy.contains('td[role="gridcell"]', 'System').click();
    cy.contains('div[role="option"]', 'Capabilities').click();
    cy.contains('Loading').should('not.be.visible');
    cy.contains('a[role="button"]', 'Create capability').click();
    cy.contains('Loading').should('not.be.visible');
    cy.contains('Select Capability Type').should('be.visible');
    cy.contains('td:visible', 'Snyk Security Configuration')
      .should('be.visible')
      .click();
    cy.get('input[name="property_snyk.api.token"]')
      .should('be.visible')
      .type(Cypress.env('snykToken'));
    cy.get('input[name="property_snyk.organization.id"]').type(
      Cypress.env('snykOrg'),
    );
    cy.contains('a:visible', 'Create capability').should('be.visible').click();
    cy.contains('Capability created: Snyk Security Configuration').should('be.visible');
    cy.get('a[data-qtip="Sign out"]').should('be.visible').click();
  });
});
