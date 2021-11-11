const AuthenticationException = require('../authenticationException')
class Authenticate {        
    constructor(...guards){
        this.$guards = guards;
    }
    async handle({ request, next }) {
        await this.authenticate(request,this.$guards);
        return next();
    }

    async authenticate($request, $guards) {
        if (empty($guards)) {
            $guards = [null];
        }

        for (let $guard of $guards) {
            if (await $request.auth.guard($guard).check()) {
                return await $request.auth.shouldUse($guard)
            }
        }

        this.unauthenticated($request, $guards);
    }

    unauthenticated($request, $guards) {
        throw new AuthenticationException(
            'Unauthenticated.', $guards, this.redirectTo($request)
        );
    }

    redirectTo($request) {
        //
    }
}

module.exports = Authenticate