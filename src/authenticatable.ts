import type { IAuthenticatable } from '@ostro/contracts/auth/authenticatable';

/**
 * Class Authenticatable.
 */
class Authenticatable implements IAuthenticatable {
    [key: string]: any;

    public $rememberTokenName: string = 'remember_token';
    public $apiTokenName: string = 'api_token';

    /**
     * Get the name of the unique identifier for the user.
     *
     * @returns The auth identifier column/field name
     */
    public getAuthIdentifierName(): string {
        return this.getKeyName();
    }

    /**
     * Get the unique identifier for the user.
     *
     * @returns The unique identifier value
     */
    public getAuthIdentifier(): any {
        return this[this.getAuthIdentifierName()];
    }

    /**
     * Get the unique broadcast identifier for the user.
     *
     * @returns The broadcast identifier value
     */
    public getAuthIdentifierForBroadcasting(): any {
        return this.getAuthIdentifier();
    }

    /**
     * Get the password for the user.
     *
     * @returns The user's hashed password
     */
    public getAuthPassword(): any {
        return this.password;
    }

    /**
     * Get the token value for the "remember me" session.
     *
     * @returns The remember token string or undefined
     */
    public getRememberToken(): any {
        if (this.getRememberTokenName()) {
            return this[this.getRememberTokenName()];
        }
    }

    /**
     * Set the token value for the "remember me" session.
     *
     * @param value - The remember token value
     */
    public setRememberToken(value: any): void {
        if (this.getRememberTokenName()) {
            this[this.getRememberTokenName()] = value;
        }
    }

    /**
     * Get the column name for the "remember me" token.
     *
     * @returns The remember token column name
     */
    public getRememberTokenName(): string {
        return this.$rememberTokenName;
    }

    /**
     * Get the token value for the API session.
     *
     * @returns The API token string or undefined
     */
    public getApiToken(): any {
        if (this.getApiTokenName()) {
            return this[this.getApiTokenName()];
        }
    }

    /**
     * Set the token value for the API session.
     *
     * @param value - The API token value
     */
    public setApiToken(value: any): void {
        if (this.getApiTokenName()) {
            this[this.getApiTokenName()] = value;
        }
    }

    /**
     * Get the column name for the API token.
     *
     * @returns The API token column name
     */
    public getApiTokenName(): string {
        return this.$apiTokenName;
    }
}

export default Authenticatable;