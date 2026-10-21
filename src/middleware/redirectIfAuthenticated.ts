import { empty } from '@ostro/support/function';

/**
 * Class RedirectIfAuthenticated.
 */
class RedirectIfAuthenticated {
    public $guards: (string | null)[];

    /**
     * Create a new RedirectIfAuthenticated middleware instance.
     *
     * @param $guards - List of guards to verify
     */
    constructor(...$guards: any[]) {
        this.$guards = $guards;
    }

    /**
     * Handle an incoming request.
     *
     * @param context - Request context containing request, next, auth and redirect
     * @returns Next result or redirect response
     */
    public async handle({
        request,
        next,
        auth,
        redirect,
    }: {
        request: any;
        next: () => any;
        auth: any;
        redirect: any;
    }): Promise<any> {
        const $guards = empty(this.$guards) ? [null] : this.$guards;

        for (const $guard of $guards) {
            if (await auth.guard($guard).check()) {
                return redirect.to(this.redirectTo(request));
            }
        }

        return next();
    }

    /**
     * Get the default redirection path when authenticated.
     *
     * @param $request - Request instance
     * @returns Redirect URL path
     */
    public redirectTo($request: any): string {
        return '/';
    }
}

export default RedirectIfAuthenticated;