const util = require('util'),
    OAuth2Strategy = require('passport-oauth2'),
    InternalOAuthError = require('passport-oauth2').InternalOAuthError;
/**
 * `Strategy` constructor.
 * 
 * Pizza-auth-2 provides an OAuth2 service.
 * 
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and `profile`, and then calls the `cb` callback supplying a `user`,
 * which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 * 
 * Options:
 * - 'pizzaAuthURL`
 * - `clientID`
 * - `clientSecret`
 * - `callbackURL`
 * 
 * @constructor
 * @param {object} option 
 * @param {function} verify 
 * @access public
 */
function Strategy(options, verify) {
    options = options || {};

    options.authorizationURL = options.pizzaAuthURL + '/oauth/authorize';
    options.tokenURL = options.pizzaAuthURL + '/oauth/token';
    
    const basicAuth = 'Basic ' + new Buffer(options.clientID + ":" + options.clientSecret).toString("base64");
    options.customHeaders = {'Authorization': basicAuth};

  
    OAuth2Strategy.call(this, options, verify);
    this.name = 'pizza';
    this._userProfileURL = options.pizzaAuthURL + '/oauth/verify';
    this._oauth2.useAuthorizationHeaderforGET(true);

}

util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.userProfile = function(accessToken, done) {
    
    this._oauth2.get(this._userProfileURL, accessToken, (err, body, res) => {
        let json;

        if (err) {
            return done(new InternalOAuthError(err));
        }

        try {
            json = JSON.parse(body);
        } catch (ex) {
            return done(new Error('Failed to parse user profile'));
        }

        done(null, json);
    });
}

module.exports = Strategy;