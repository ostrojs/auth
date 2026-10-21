import AuthenticationException from '../authenticationException';
import { empty } from '@ostro/support/function';

/**
 * Class Authenticate.
 */
class Authenticate {
    public $guards: (string | null)[];

    /**
     * Create a new Authenticate middleware instance.
     *
     * @param guards - List of guards to check
     */
    constructor(...guards: any[]) {
        this.$guards = guards;
    }

    /**
     * Handle an incoming request.
     *
     * @param context - Request context containing request and next
     * @returns Next middleware result
     */
    public async handle({ request, next }: { request: any; next: () => any }): Promise<any> {
        await this.authenticate(request, this.$guards);
        return next();
    }

    /**
     * Determine if the request user is authenticated by checking guards.
     *
     * @param $request - Request instance
     * @param $guards - Array of guards
     * @returns Authenticated user
     */
    public async authenticate($request: any, $guards: any[]): Promise<any> {
        if (empty($guards)) {
            $guards = [null];
        }

        for (const $guard of $guards) {
            if (await $request.auth.guard($guard).check()) {
                return await $request.auth.shouldUse($guard);
            }
        }

        this.unauthenticated($request, $guards);
    }

    /**
     * Handle unauthenticated user attempt.
     *
     * @param $request - Request instance
     * @param $guards - Array of guards that were checked
     */
    public unauthenticated($request: any, $guards: any[]): never {
        throw new AuthenticationException(
            'Unauthenticated.',
            $guards,
            this.redirectTo($request)
        );
    }

    /**
     * Get the redirection path for unauthenticated users.
     *
     * @param $request - Request instance
     * @returns Redirect path or undefined
     */
    public redirectTo($request: any): any {
        //
    }
}

export default Authenticate;