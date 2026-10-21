/**
 * Class AuthenticationException.
 */
class AuthenticationException extends Error {
    /**
     * All of the guards that were checked.
     */
    public $guards: (string | null)[];

    /**
     * The path the user should be redirected to.
     */
    public $redirectTo: string | null;

    /**
     * Create a new authentication exception.
     *
     * @param $message - The exception error message
     * @param $guards - The guards that were checked
     * @param $redirectTo - The redirection target path
     */
    constructor($message: string = 'Unauthenticated.', $guards: (string | null)[] = [], $redirectTo: string | null = null) {
        super($message);
        this.name = this.constructor.name;
        this.$guards = $guards;
        this.$redirectTo = $redirectTo;
    }

    /**
     * Get the guards that were checked.
     *
     * @returns Array of guard names
     */
    public guards(): (string | null)[] {
        return this.$guards;
    }

    /**
     * Get the path the user should be redirected to.
     *
     * @returns Redirection target path or null
     */
    public redirectTo(): string | null {
        return this.$redirectTo;
    }
}

export default AuthenticationException;