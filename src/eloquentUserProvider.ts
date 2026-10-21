import { empty, count, is_array, is_null } from '@ostro/support/function';

/**
 * Class EloquentUserProvider.
 */
class EloquentUserProvider {
    public $model: any;
    public $hasher: any;

    /**
     * Create a new Eloquent user provider.
     *
     * @param $hasher - Hasher implementation
     * @param $model - Eloquent model class or constructor
     */
    constructor($hasher: any, $model: any) {
        this.$model = $model;
        this.$hasher = $hasher;
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param $identifier - Primary key value
     * @returns Query promise resolving to user model
     */
    public retrieveById($identifier: any): any {
        const $model = this.createModel();

        return this.newModelQuery($model)
            .where($model.getAuthIdentifierName(), $identifier)
            .first();
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param $identifier - Primary key value
     * @param $token - Remember token string
     * @returns Retrieved model or null
     */
    public async retrieveByToken($identifier: string, $token: string): Promise<any> {
        const $model = this.createModel();

        const $retrievedModel = await this.newModelQuery($model)
            .where($model.getAuthIdentifierName(), $identifier)
            .first();

        if (!$retrievedModel) {
            return;
        }

        const $rememberToken = $retrievedModel.getRememberToken();
        return $rememberToken && $rememberToken == $token ? $retrievedModel : null;
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param $user - User model
     * @param $token - New remember token
     * @returns Save promise
     */
    public updateRememberToken($user: Record<string, any>, $token: string): any {
        $user.setRememberToken($token);

        return $user.save();
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param $credentials - User credentials dictionary
     * @returns Query promise resolving to user model
     */
    public retrieveByCredentials($credentials: Record<string, any>): any {
        if (
            empty($credentials) ||
            (count($credentials) === 1 && (String as any).contains(this.firstCredentialKey($credentials), 'password'))
        ) {
            return;
        }

        const $query = this.newModelQuery();

        for (const $key in $credentials) {
            const $value = $credentials[$key];
            if ((String as any).contains($key, 'password')) {
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

    /**
     * Get the first credential key from credentials object.
     *
     * @param $credentials - User credentials
     * @returns First key name or undefined
     */
    public firstCredentialKey($credentials: Record<string, any>): string | undefined {
        for (const $key in $credentials) {
            return $key;
        }
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param $user - User model
     * @param $credentials - User credentials
     * @returns True if password matches
     */
    public validateCredentials($user: Record<string, any>, $credentials: Record<string, any>): boolean {
        const $plain = $credentials['password'];
        return this.$hasher.check($plain, $user.getAuthPassword());
    }

    /**
     * Get a new query builder for the model instance.
     *
     * @param $model - Optional model instance
     * @returns Query builder instance
     */
    public newModelQuery($model: any = null): any {
        return is_null($model) ? this.createModel().newQuery() : $model.newQuery();
    }

    /**
     * Create a new instance of the model.
     *
     * @returns New model instance
     */
    public createModel(): any {
        return new this.$model();
    }

    /**
     * Get the hasher implementation.
     *
     * @returns Hasher instance
     */
    public getHasher(): any {
        return this.$hasher;
    }

    /**
     * Set the hasher implementation.
     *
     * @param $hasher - Hasher instance
     * @returns Current instance
     */
    public setHasher($hasher: any): this {
        this.$hasher = $hasher;

        return this;
    }

    /**
     * Get the model class name or constructor.
     *
     * @returns Model constructor
     */
    public getModel(): any {
        return this.$model;
    }

    /**
     * Set the model class name or constructor.
     *
     * @param $model - Model constructor
     * @returns Current instance
     */
    public setModel($model: any): this {
        this.$model = $model;

        return this;
    }
}

export default EloquentUserProvider;