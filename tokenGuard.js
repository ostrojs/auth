const GuardHelpers = require('./guardHelpers')
const { implement } = require('@ostro/support/function')
const { createHash } = require('crypto');
const Crypt = require('@ostro/support/facades/crypt')

class TokenGuard extends GuardHelpers {

    $hash;

    $request;

    $provider;

    $inputKey = 'api_token';

    $storageKey = 'api_token';

    constructor($provider, $request, $inputKey = 'api_token', $storageKey = 'api_token', $hash = false) {
        super()
        this.$hash = $hash;
        this.$request = $request;
        this.$provider = $provider;
        this.$inputKey = $inputKey;
        this.$storageKey = $storageKey;
    }

    async hasValidCredentials($user, $credentials) {
        return !is_null($user) && await this.$provider.validateCredentials($user, $credentials);

    }

    async attempt($credentials = {}) {
        let $user = await this.$provider.retrieveByCredentials($credentials);
        this.$lastAttempted = $user;

        if (await this.hasValidCredentials($user, $credentials)) {
            this.$user = $user;
            await this.user();

            return true;
        }

        return false;
    }

    async user() {

        if (!is_null(this.$user)) {
            return this.$user;
        }

        let $user = null;

        let $token = this.getTokenForRequest();
        if (!empty($token)) {
            $user = await this.$provider.retrieveByCredentials({
                [this.$storageKey]: this.$hash ? createHash('sha256').update($token).digest('hex') : $token,
            });
        }

        return this.$user = $user;
    }

    getTokenForRequest() {
        let $token = this.$request.getQuery(this.$inputKey);
        if (empty($token)) {
            $token = this.$request.input(this.$inputKey);
        }

        if (empty($token)) {
            $token = this.$request.bearerToken();
        }

        if (empty($token)) {
            $token = this.$request.getPassword();
        }

        return $token;
    }

    async validate($credentials = {}) {

        if (empty($credentials[this.$inputKey])) {
            return false;
        }

        $credentials = {
            [this.$storageKey]: $credentials[this.$inputKey]
        };

        if (await this.$provider.retrieveByCredentials($credentials)) {
            return true;
        }

        return false;
    }

}

module.exports = TokenGuard