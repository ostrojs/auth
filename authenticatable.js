class Authenticatable {

    $rememberTokenName = 'remember_token';
    
    $apiTokenName = 'api_token';

    getAuthIdentifierName() {
        return this.getKeyName();
    }

    getAuthIdentifier() {
        return this[this.getAuthIdentifierName()];
    }

    getAuthIdentifierForBroadcasting() {
        return this.getAuthIdentifier();
    }

    getAuthPassword() {
        return this.password;
    }

    getRememberToken() {
        if (this.getRememberTokenName()) {
            return this[this.getRememberTokenName()];
        }
    }

    setRememberToken($value) {
        if (this.getRememberTokenName()) {
            this[this.getRememberTokenName()] = $value;
        }
    }

    getRememberTokenName() {
        return this.$rememberTokenName;
    }

    getApiToken() {
        if (this.getApiTokenName()) {
            return this[this.getApiTokenName()];
        }
    }

    setApiToken($value) {
        if (this.getApiTokenName()) {
            this[this.getApiTokenName()] = $value;
        }
    }

    getApiTokenName() {
        return this.$apiTokenName;
    }
}

module.exports = Authenticatable