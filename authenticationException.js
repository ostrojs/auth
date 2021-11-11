class AuthenticationException extends Error {
    /**
     * All of the guards that were checked.
     *
     * @var array
     */
    $guards;

    /**
     * The path the user should be redirected to.
     *
     * @var string
     */
    $redirectTo;

    /**
     * Create a new authentication exception.
     *
     */
    constructor($message = 'Unauthenticated.', $guards = [], $redirectTo = null) {
        super($message);
        this.$guards = $guards;
        this.$redirectTo = $redirectTo;
    }

    /**
     * Get the guards that were checked.
     *
     */
    guards() {
        return this.$guards;
    }

    /**
     * Get the path the user should be redirected to.
     *
     */
    redirectTo() {
        return this.$redirectTo;
    }
}
module.exports = AuthenticationException