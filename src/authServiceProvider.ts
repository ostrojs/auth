import ServiceProvider from '@ostro/support/serviceProvider';
import AuthManager from './authManager';
import { call_user_func } from '@ostro/support/function';

/**
 * Class AuthServiceProvider.
 */
class AuthServiceProvider extends ServiceProvider {
    declare public $app: any;

    /**
     * Register authentication service bindings.
     */
    public register(): void {
        this.registerAuthenticator();
    }

    /**
     * Register the authenticator manager singleton.
     */
    public registerAuthenticator(): void {
        this.$app.singleton('auth', function ($app: any) {
            return new AuthManager($app);
        });
    }

    /**
     * Bootstrap the authentication services.
     */
    public boot(): void {
        this.$app.singleton('auth.driver', function ($app: any) {
            return $app['auth'].guard();
        });
    }

    /**
     * Register the authenticatable user resolver.
     */
    public registerUserResolver(): void {
        this.$app.bind('@ostro/contracts/auth/authenticatable', function ($app: any) {
            return call_user_func($app['auth'].userResolver());
        });
    }

    /**
     * Register the request rebinding handler.
     */
    public registerRequestRebindHandler(): void {
        this.$app.rebinding('request', function ($app: any, $request: any) {
            $request.setUserResolver(function ($guard: any = null) {
                return call_user_func($app['auth'].userResolver(), $guard);
            });
        });
    }
}

export default AuthServiceProvider;