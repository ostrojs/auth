import AuthManager from '../authManager';

/**
 * Class StartAuth.
 */
class StartAuth {
    declare public $app: any;
    public $auth: any;
    public $registered: boolean = false;
    public $startAuth: any;

    /**
     * Create a new StartAuth middleware instance.
     */
    constructor() {
        this.$auth = this.$app?.['auth'];

        if (this.$auth instanceof AuthManager) {
            this.$registered = true;
            this.$startAuth = this.$auth.start();
        }
    }

    /**
     * Handle an incoming request.
     *
     * @param context - Request context containing request, response, and next
     * @returns Next result or executed startAuth handler
     */
    public handle({
        request,
        response,
        next,
    }: {
        request: any;
        response: any;
        next: (err?: any) => any;
    }): any {
        if (!this.$registered) {
            return next();
        }

        return this.$startAuth(request, response, next);
    }
}

export default StartAuth;