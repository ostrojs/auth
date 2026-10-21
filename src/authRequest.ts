import { Macroable } from '@ostro/support/macro';

/**
 * Class Auth.
 */
class Auth extends Macroable {
    public $request: any;
    public $manager: any;
    public $defaultGuard: string;
    public $guards: Record<string, any>;

    /**
     * Create a new auth request instance.
     *
     * @param request - HTTP request instance
     * @param manager - Auth manager instance
     */
    constructor(request: any, manager: any) {
        super();
        Object.defineProperties(this, {
            $request: {
                value: request,
            },
            $manager: {
                value: manager,
            },
            $defaultGuard: {
                value: manager.getDefaultDriver(),
                writable: true,
            },
            $guards: {
                value: {},
                writable: true,
            },
        });
    }

    /**
     * Resolve the given guard instance by name.
     *
     * @param $name - Guard name
     * @returns Guard instance
     */
    public guard($name?: string): any {
        if (!$name) {
            $name = this.$defaultGuard;
        }
        return (this.$guards[$name] = this.$guards[$name] || this.$manager.guard($name)(this.$request));
    }

    /**
     * Set the default guard and return its user.
     *
     * @param $name - Guard name
     * @returns The user instance
     */
    public shouldUse($name?: string): any {
        $name = $name || this.$defaultGuard;

        this.setDefaultDriverForCurrentRequest($name);

        return this.guard($name).user();
    }

    /**
     * Set the default guard driver for the current request.
     *
     * @param $name - Guard name
     */
    public setDefaultDriverForCurrentRequest($name: string): void {
        this.$defaultGuard = $name;
    }

    /**
     * Magic getter to forward calls to default guard.
     *
     * @param target - Target object
     * @param method - Method name
     * @returns Resolved property or method
     */
    public __get(target: Record<string, any>, method: string): any {
        return this.make(target.guard(this.$defaultGuard), method);
    }
}

export default Auth;