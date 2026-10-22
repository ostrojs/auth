import Manager from '@ostro/support/manager';
import InvalidArgumentException from '@ostro/support/exceptions/invalidArgumentException';
import CreatesUserProviders from './createsUserProviders';
import SessionGuard from './sessionGuard';
import TokenGuard from './tokenGuard';
import AuthRequest from './authRequest';
import { implement, count } from '@ostro/support/function';

/**
 * Class AuthManager.
 */
class AuthManager extends (implement(Manager, CreatesUserProviders) as any) {
    public $type: string = 'auth';
    public $userResolver: any;
    declare public $drivers: Record<string, any>;
    declare public $customProviderCreators: Record<string, any>;
    declare public createUserProvider: (provider?: any) => any;

    /**
     * Create a new AuthManager instance.
     *
     * @param $app - Application container instance
     */
    constructor($app: any) {
        super($app);
        Object.defineProperties(this, {
            $userResolver: {
                value: function (this: any, $guard: any = null) {
                    return this.guard($guard).user();
                },
                writable: true,
            },
        });
    }

    /**
     * Attempt to get the guard from the local cache.
     *
     * @param $name - Guard name
     * @returns Guard instance
     */
    public guard($name: any = null): any {
        return this.driver($name);
    }

    /**
     * Resolve the given guard by name.
     *
     * @param $name - Guard name
     * @returns Guard driver instance
     */
    public resolve($name: string): any {
        const $config = this.getConfig($name);
        if (!$config) {
            throw new InvalidArgumentException(`Auth guard [${$name}] is not defined.`);
        }
        return super.resolve($name, $config);
    }

    /**
     * Middleware to initiate auth on each request.
     *
     * @returns Middleware function
     */
    public start(): (request: any, response: any, next: (err?: any) => any) => void {
        return (request: any, response: any, next: (err?: any) => any) => {
            request.auth = new AuthRequest(request, this);
            request.user = function (this: any, $guard: any) {
                return this.auth.guard($guard).user();
            };
            next();
        };
    }

    /**
     * Create an instance of the session guard driver.
     *
     * @param $config - Driver configuration
     * @param $name - Guard name
     * @returns Factory function creating SessionGuard
     */
    public createSessionDriver($config: Record<string, any>, $name: string): (request: any) => SessionGuard {
        const $provider = this.createUserProvider($config['provider'] || null);

        return ($request: any) => {
            return new SessionGuard($name, $provider, $request);
        };
    }

    /**
     * Create an instance of the token guard driver.
     *
     * @param $config - Driver configuration
     * @param $name - Guard name
     * @returns Factory function creating TokenGuard
     */
    public createTokenDriver($config: Record<string, any>, $name: string): (request: any) => TokenGuard {
        const $provider = this.createUserProvider($config['provider'] || null);
        return ($request: any) => {
            return new TokenGuard(
                $provider,
                $request,
                $config['input_key'] || 'api_token',
                $config['storage_key'] || 'api_token',
                $config['hash'] || false
            );
        };
    }

    /**
     * Get the guard configuration.
     *
     * @param name - Guard name
     * @returns Configuration object
     */
    public getConfig(name: string): any {
        return super.getConfig(`guards.${name}`);
    }

    /**
     * Get the default authentication driver name.
     *
     * @returns Default driver name
     */
    public getDefaultDriver(): string {
        return super.getConfig(`defaults.guard`);
    }

    /**
     * Get the default user resolver callback.
     *
     * @returns User resolver function
     */
    public userResolver(): any {
        return this.$userResolver;
    }

    /**
     * Set the callback to be used to resolve users.
     *
     * @param $userResolver - User resolver function
     * @returns Current instance
     */
    public resolveUsersUsing($userResolver: Function): this {
        this.$userResolver = $userResolver;
        return this;
    }

    /**
     * Register a custom provider creator Closure.
     *
     * @param $name - Provider name
     * @param $callback - Provider factory closure
     * @returns Current instance
     */
    public provider($name: string, $callback: Function): this {
        this.$customProviderCreators[$name] = $callback;
        return this;
    }

    /**
     * Determine if any guards have been resolved.
     *
     * @returns True if guards are resolved
     */
    public hasResolvedGuards(): boolean {
        return count(this.$drivers) > 0;
    }

    /**
     * Forget all of the resolved guard instances.
     *
     * @returns Current instance
     */
    public forgetGuards(): this {
        return this.forgetDrivers();
    }
}

export default AuthManager;