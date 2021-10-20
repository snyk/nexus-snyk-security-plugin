describe("test", () => {
  it("log in, update password, and add Snyk plugin (Capability)", () => {
    cy.visit("http://localhost:8081");
    cy.get('a[data-qtip="Sign in"]').should("be.visible").click();
    cy.get(".x-title-text").should("contain", "Sign In").should("be.visible");

    // Fill in credentials
    cy.get('input[name="username"]').type("admin");
    cy.get('input[name="password"]').type(Cypress.env("nexusPass"));
    cy.get('div[role="dialog"] a')
      .should("be.visible")
      .contains("Sign in")
      .click();
    cy.contains("User signed in").should("be.visible");

    cy.contains(
      "This wizard will help you complete required setup tasks."
    ).should("be.visible");

		// Go through the mandatory wizard to set a new password (same as the old password)
    cy.get("body").then(($body) => {
      if ($body.find('div[role="dialog"]').length) {
        cy.log("found the wizard");

        cy.get('div[role="dialog"]').then(($dialog) => {
          cy.log("in the diaglog callback");
          if ($dialog.find("a").length) {
            cy.log("found the Next button");
            cy.wrap($dialog).should("be.visible").contains("Next").click();
            cy.log("clicked the Next button");

            // Set new password
            cy.get('div[role="presentation"]').then(($presentation) => {
              cy.log("in the password page callback");
              if ($presentation.find('input[type="password"]').length) {
                cy.log("found the password text boxes");
                cy.wrap($presentation)
                  .get('input[type="password"]')
                  .each(($password) => {
                    cy.wrap($password).type(Cypress.env("nexusPass"));
                  });
                cy.log("set the passwords");

                cy.contains(
                  'div[role="dialog"] a[role="button"]:visible',
                  "Next"
                ).click();
                cy.log("clicked the Next button");
              }
            });

            // Configure Anonymous access
            cy.get('div[role="presentation"]').then(($anonymous) => {
              cy.log("in the anonymous access callback");
              if ($anonymous.find('input[type="radio"]').length) {
                cy.log("found an anonymous access radio button");
                cy.wrap($anonymous).get('div[role="radiogroup"] input').check();
                cy.log("checked the first anonymous access radio buttong");
                cy.contains(
                  'div[role="dialog"] a[role="button"]:visible',
                  "Next"
                ).click();
                cy.log("clicked the Next button");
              }
            });

            // Finish
            cy.contains(
              'div[role="dialog"] a[role="button"]:visible',
              "Finish"
            ).click();
          } else {
            cy.log("could not find the Next button");
          }
        });
      } else {
        cy.log("could not find the wizard");
      }
    });

    // Add Capability
    cy.get('a[data-qtip="Server administration and configuration"]').click();
    cy.contains('td[role="gridcell"]', "System").click();
    cy.contains('div[role="option"]', "Capabilities").click();
    cy.contains('a[role="button"]', "Create capability").click();
    cy.contains("Loading").should("not.be.visible");
    cy.contains("Select Capability Type").should("be.visible");
    cy.contains("td:visible", "Snyk Security Configuration")
      .should("be.visible")
      .click();
    cy.get('input[name="property_snyk.api.token"]')
      .should("be.visible")
      .type(Cypress.env("snykToken"));
    cy.get('input[name="property_snyk.organization.id"]').type(
      Cypress.env("snykOrg")
    );
    cy.contains("a:visible", "Create capability").should("be.visible").click();
  });
});
