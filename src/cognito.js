const CognitoExpress = require('cognito-express');

module.exports = function(app) {
  const credentials = app.get('cognito');
  app.set('cognitoClient', new CognitoExpress(credentials));
};
