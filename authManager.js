require('@ostro/support/helpers')
const { Macroable } = require('@ostro/support/macro')
const InvalidArgumentException = require('@ostro/support/exceptions/invalidArgumentException')
const CreatesUserProvider = require('./createsUserProviders')
const SessionGuard = require('./sessionGuard')
const TokenGuard = require('./tokenGuard')
const AuthRequest = require('./authRequest')

class AuthManager extends Macroable.implement(CreatesUserProvider) {

    $customCreators = {};

    $guards = {};

    constructor($app) {
        super()
        this.$app = $app;

        this.$userResolver = function($guard = null) {
            return this.guard($guard).user();
        };
    }

    guard($name = null) {
        $name = $name || this.getDefaultDriver();

        return this.$guards[$name] = this.$guards[$name] || this.resolve($name);
    }

    resolve($name) {
        let $config = this.getConfig($name);
        if (is_null($config)) {
            throw new InvalidArgumentException(`Auth guard [${$name}] is not defined.`);
        }

        if (isset(this.$customCreators[$config['driver']])) {
            return this.callCustomCreator($name, $config);
        }

        let $driverMethod = 'create' + $config['driver'].ucfirst() + 'Driver';

        if (method_exists(this, $driverMethod)) {
            return this[$driverMethod]($name, $config);
        }

        throw new InvalidArgumentException(
            `Auth driver [${$config['driver']}] for guard [${$name}] is not defined.`
        );
    }

    callCustomCreator($name, $config) {
        return this.$customCreators[$config['driver']](this.$app, $name, $config);
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

    createSessionDriver($name, $config) {
        let $provider = this.createUserProvider($config['provider'] || null);

        return ($request) => {

            return new SessionGuard($name, $provider, $request);
        }

    }

    createTokenDriver($name, $config) {

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

    getConfig($name) {
        return this.$app['config'][`auth.guards`][$name];
    }

    getDefaultDriver() {
        return this.$app['config']['auth.defaults.guard'];
    }

    userResolver() {
        return this.$userResolver;
    }

    resolveUsersUsing($userResolver) {
        this.$userResolver = $userResolver;

        return this;
    }

    extend($driver, $callback) {
        this.$customCreators[$driver] = $callback;

        return this;
    }

    provider($name, $callback) {
        this.customProviderCreators[$name] = $callback;

        return this;
    }

    hasResolvedGuards() {
        return count(this.$guards) > 0;
    }

    forgetGuards() {
        this.$guards = [];

        return this;
    }

    setApplication($app) {
        this.$app = $app;

        return this;
    }

    __get($target, $method) {
        return this.make($target.guard(), $method);
    }
}

module.exports = AuthManager