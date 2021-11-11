const GenericUser = require('./genericUser')
class DatabaseUserProvider {

    $conn;

    $table;

    $hasher;

    constructor($conn, $hasher, $table) {
        this.$conn = $conn;
        this.$table = $table;
        this.$hasher = $hasher;
    }

    async retrieveById($identifier) {
        let $user = await this.$conn.table(this.$table).find($identifier);

        return this.getGenericUser($user);
    }

    async retrieveByToken($identifier, $token) {
        let $user = this.getGenericUser(
            await this.$conn.table(this.$table).where($identifier, $token).first()
        );

        return $user && $user.getRememberToken() && hash_equals($user.getRememberToken(), $token) ?
            $user : null;
    }

    async updateRememberToken($user, $token) {
        await this.$conn.table(this.$table)
            .where($user.getAuthIdentifierName(), $user.getAuthIdentifier())
            .update({
                [$user.getRememberTokenName()]: $token
            });
    }

    async retrieveByCredentials($credentials = {}) {
        if (empty($credentials) || (count($credentials) === 1 && String.contains(this.firstCredentialKey($credentials), 'password'))) {
            return;
        }

        let $query = this.$conn.table(this.$table);

        for (let $key in $credentials) {
            let $value = $credentials[$key]
            if (String.contains($key, 'password')) {
                continue;
            }

            if (Array.isArray($value) || $value instanceof Array) {
                $query.whereIn($key, $value);
            } else {
                $query.where($key, $value);
            }
        }

        let $user = await $query.first();

        return this.getGenericUser($user);
    }

    firstCredentialKey($credentials) {
        for (let $key in $credentials) {
            return $key;
        }
    }

    getGenericUser($user) {
        if (!is_null($user)) {
            return new GenericUser($user);
        }
    }

    validateCredentials($user, $credentials = {}) {
        return this.$hasher.check(
            $credentials['password'], $user.getAuthPassword()
        );
    }
}

module.exports = DatabaseUserProvider