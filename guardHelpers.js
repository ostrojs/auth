class GuardHelpers {

    async authenticate() {
        let $user = await this.user()
        if (!is_null($user)) {
            return $user;
        }

        throw new AuthenticationException;
    }

    hasUser() {
        return !is_null(this.$user);
    }

    async check() {
        return !is_null(await this.user());
    }

    async guest() {
        return !await this.check();
    }

    async id() {
        if (await this.user()) {
            return (await this.user()).getAuthIdentifier();
        }
    }

    setUser($user) {
        this.$user = $user;

        return this;
    }

    getProvider() {
        return this.$provider;
    }

    setProvider($provider) {
        this.$provider = $provider;
    }
}

module.exports = GuardHelpers