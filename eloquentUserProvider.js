class EloquentUserProvider {

    $model;

    $hasher;

    constructor($hasher, $model) {
        this.$model = $model;
        this.$hasher = $hasher;
    }

    retrieveById($identifier) {
        let $model = this.createModel();

        return this.newModelQuery($model)
            .where($model.getAuthIdentifierName(), $identifier)
            .first();
    }

    async retrieveByToken($identifier, $token) {
        let $model = this.createModel();

        let $retrievedModel = await this.newModelQuery($model).where(
            $model.getAuthIdentifierName(), $identifier
        ).first();

        if (!$retrievedModel) {
            return;
        }

        let $rememberToken = $retrievedModel.getRememberToken();
        return $rememberToken && $rememberToken == $token ?
            $retrievedModel : null;
    }

    updateRememberToken($user, $token) {
        $user.setRememberToken($token);

        return $user.save();

    }

    retrieveByCredentials($credentials) {
        if (empty($credentials) ||
            (count($credentials) === 1 &&
                String.contains(this.firstCredentialKey($credentials), 'password'))) {
            return;
        }

        let $query = this.newModelQuery();

        for (let $key in $credentials) {
            let $value = $credentials[$key]
            if (String.contains($key, 'password')) {
                continue;
            }
            if (is_array($value) || $value instanceof Array) {
                $query.whereIn($key, $value);
            } else {
                $query.where($key, $value);
            }
        }

        return $query.first();
    }

    firstCredentialKey($credentials) {
        for (let $key in $credentials) {
            return $key;
        }
    }

    validateCredentials($user, $credentials) {
        let $plain = $credentials['password'];
        return this.$hasher.check($plain, $user.getAuthPassword());
    }

    newModelQuery($model = null) {
        return is_null($model) ?
            this.createModel().newQuery() :
            $model.newQuery();
    }

    createModel() {
        return new this.$model;
    }

    getHasher() {
        return this.$hasher;
    }

    setHasher($hasher) {
        this.$hasher = $hasher;

        return this;
    }

    getModel() {
        return this.$model;
    }

    setModel($model) {
        this.$model = $model;

        return this;
    }
}

module.exports = EloquentUserProvider