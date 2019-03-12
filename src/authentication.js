const { ExtractJwt } = require('passport-jwt');
const authentication = require('@feathersjs/authentication');
const custom = require('feathers-authentication-custom');
const jwt = require('@feathersjs/authentication-jwt');

class CustomVerifier {
  constructor(app) {
    const cognitoClient = app.get('cognitoClient');

    if (!cognitoClient) throw new Error('cognitoClient is not configured');

    this._app = app;
    this._cognitoClient = cognitoClient;
  }

  async verify(req, done) {
    let user = false;
    let payload;

    const extractors = [
      ExtractJwt.fromAuthHeaderWithScheme('Bearer'),
      ExtractJwt.fromBodyField('idToken')
    ];

    const token = extractors.reduce((t, fn) => {
      if (t) return t;
      t = fn(req);
      return t;
    }, '');

    if (token) {
      payload = await this._validateToken(token);

      // I store a user record with a feathers user service
      // You could alternatively return a user object
      // constructed from the cognitor jwt payload

      /*
      const data = {
        email: payload.email,
        emailVerified: payload.email_verified,
        externalUserIdentifier: payload['cognito:username'],
        groups: payload['cognito:groups'],
        phonenumber: payload.phone_number,
        phonenumberVerified: payload.phone_number_verified
      };

      const params = { mongoose: { upsert: true } };

      const queryResults = await this._app
        .service('user')
        .find({ query: { email: payload.email } });

      if (!queryResults.data || queryResults.data.length > 1) return;

      const userId = queryResults.data[0]._id;

      user = await this._app.service('user').patch(userId, data, params);
      */

      user = {
        email: payload.email,
        emailVerified: payload.email_verified,
        externalUserIdentifier: payload['cognito:username'],
        groups: payload['cognito:groups'],
        phonenumber: payload.phone_number,
        phonenumberVerified: payload.phone_number_verified
      };
    }

    done(null, user, { id: user.email });
  }

  _validateToken(token) {
    return new Promise((resolve, reject) => {
      this._cognitoClient.validate(token, (ex, resp) => {
        if (ex) {
          reject(ex);
        }

        resolve(resp);
      });
    });
  }
}

module.exports = function(app) {
  const config = app.get('authentication');

  // Set up authentication with the secret
  app.configure(authentication(config));
  app.configure(jwt());
  app.configure(custom({ name: 'cognito', Verifier: CustomVerifier }));

  // The `authentication` service is used to create a JWT.
  // The before `create` hook registers strategies that can be used
  // to create a new valid JWT (e.g. local or oauth2)
  app.service('authentication').hooks({
    before: {
      create: [authentication.hooks.authenticate(['cognito', 'jwt'])],
      remove: [authentication.hooks.authenticate('cognito')]
    }
  });
};
