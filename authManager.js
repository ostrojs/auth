require('@ostro/support/helpers')
const Manager = require('@ostro/support/manager')
const InvalidArgumentException = require('@ostro/support/exceptions/invalidArgumentException')
const CreatesUserProvider = require('./createsUserProviders')
const SessionGuard = require('./sessionGuard')
const TokenGuard = require('./tokenGuard')
const AuthRequest = require('./authRequest')

class AuthManager extends implement(Manager,CreatesUserProvider) {

    $type = 'auth';

    constructor($app) {
        super($app)

        this.$userResolver = function($guard = null) {
            return this.guard($guard).user();
        };
    }

    guard($name = null) {
        return this.driver($name)
    }

    resolve($name) {
        let $config = this.getConfig($name);
        if (!$config) {
            throw new InvalidArgumentException(`Auth guard [${$name}] is not defined.`);
        }
        return super.resolve($name, $config)
    }

    start() {
        return (request, response, next) => {
            request.auth = new AuthRequest(request, this)
            request.user = function($guard) {
                return this.auth.guard($guard).user()
            }
            next()
        }
    }

    createSessionDriver($config, $name) {
        let $provider = this.createUserProvider($config['provider'] || null);

        return ($request) => {

            return new SessionGuard($name, $provider, $request);
        }

    }

    createTokenDriver($config, $name) {

        let $provider = this.createUserProvider($config['provider'] || null)
        return ($request) => {
            return new TokenGuard(
                $provider,
                $request,
                $config['input_key'] || 'api_token',
                $config['storage_key'] || 'api_token',
                $config['hash'] || false
            );
        }

    }

    getConfig(name) {
        return super.getConfig(`guards.${name}`);
    }

    getDefaultDriver() {
        return super.getConfig(`defaults.guard`);
    }

    userResolver() {
        return this.$userResolver;
    }

    resolveUsersUsing($userResolver) {
        this.$userResolver = $userResolver;
        return this;
    }

    provider($name, $callback) {
        this.$customProviderCreators[$name] = $callback;
        return this;
    }

    hasResolvedGuards() {
        return count(this.$driver) > 0;
    }

    forgetGuards() {
        return this.forgetDrivers()
    }

}

module.exports = AuthManager