class RedirectIfAuthenticated {
    constructor(...$guards) {
        this.$guards = $guards;
    }

    async handle({ request, next, auth, redirect }) {
        let $guards = empty(this.$guards) ? [null] : this.$guards;

        for (let $guard of $guards) {
            if (await auth.guard($guard).check()) {
                return redirect.to(this.redirectTo(request));
            }
        }

        return next();
    }

    redirectTo($request) {
        return '/';
    }
}

module.exports = RedirectIfAuthenticated