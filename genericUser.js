const GenericUserInterface = require('@ostro/contracts/auth/genericUser')
class GenericUser extends GenericUserInterface {

    constructor($attributes) {
        super()
        this.$attributes = $attributes;
    }

    getAuthIdentifierName() {
        return 'id';
    }

    getAuthIdentifier() {
        return this.$attributes[this.getAuthIdentifierName()];
    }

    getAuthPassword() {
        return this.$attributes['password'];
    }

    getRememberToken() {
        return this.$attributes[this.getRememberTokenName()];
    }

    setRememberToken($value) {
        this.$attributes[this.getRememberTokenName()] = $value;
    }

    getRememberTokenName() {
        return 'remember_token';
    }

    setApiToken($value) {
        this.$attributes[this.getApiTokenName()] = $value;
    }

    getApiTokenName() {
        return 'api_token';
    }

    toJSON() {
        return this.$attributes
    }


    __get($key) {
        return this.$attributes[$key];
    }

    __set($key, $value) {
        this.$attributes[$key] = $value;
    }


}

module.exports = GenericUser