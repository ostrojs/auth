const ServiceProvider = require('@ostro/support/serviceProvider')
const AuthManager = require('./authManager')
class AuthServiceProvider extends ServiceProvider {

    register() {
        this.registerAuthenticator();

    }

    registerAuthenticator() {
        this.$app.singleton('auth', function($app) {
            return new AuthManager($app);
        });

    }
    boot() {
        this.$app.singleton('auth.driver', function($app) {
            return $app['auth'].guard();
        });
    }

    registerUserResolver() {
        this.$app.bind('@ostro/contracts/auth/authenticatable', function($app) {
            return call_user_func($app['auth'].userResolver());
        });
    }

    registerRequestRebindHandler() {
        this.$app.rebinding('request', function($app, $request) {
            $request.setUserResolver(function($guard = null) {
                return call_user_func($app['auth'].userResolver(), $guard);
            });
        });
    }

}

module.exports = AuthServiceProvider