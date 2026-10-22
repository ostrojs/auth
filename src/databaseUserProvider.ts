import GenericUser from './genericUser';
import { hash_equals, empty, count, is_null } from '@ostro/support/function';
import { contains } from '@ostro/support/string';

/**
 * Class DatabaseUserProvider.
 */
class DatabaseUserProvider {
    public $conn: any;
    public $table: string;
    public $hasher: any;

    /**
     * Create a new database user provider.
     *
     * @param $conn - Database connection instance
     * @param $hasher - Hasher implementation
     * @param $table - Database table name
     */
    constructor($conn: any, $hasher: any, $table: string) {
        this.$conn = $conn;
        this.$table = $table;
        this.$hasher = $hasher;
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param $identifier - Primary key value
     * @returns Generic user or undefined
     */
    public async retrieveById($identifier: any): Promise<GenericUser | undefined> {
        const $user = await this.$conn.table(this.$table).find($identifier);

        return this.getGenericUser($user);
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param $identifier - Primary key column or value
     * @param $token - Remember token string
     * @returns Generic user or null
     */
    public async retrieveByToken($identifier: string, $token: string): Promise<GenericUser | null> {
        const $user = this.getGenericUser(
            await this.$conn.table(this.$table).where($identifier, $token).first()
        );

        return $user && $user.getRememberToken() && hash_equals($user.getRememberToken(), $token)
            ? $user
            : null;
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param $user - User instance
     * @param $token - New remember token
     */
    public async updateRememberToken($user: Record<string, any>, $token: string): Promise<void> {
        await this.$conn
            .table(this.$table)
            .where($user.getAuthIdentifierName(), $user.getAuthIdentifier())
            .update({
                [$user.getRememberTokenName()]: $token,
            });
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param $credentials - User credentials dictionary
     * @returns Generic user or undefined
     */
    public async retrieveByCredentials($credentials: Record<string, any> = {}): Promise<GenericUser | undefined> {
        if (
            empty($credentials) ||
            (count($credentials) === 1 && contains(this.firstCredentialKey($credentials), 'password'))
        ) {
            return;
        }

        const $query = this.$conn.table(this.$table);

        for (const $key in $credentials) {
            const $value = $credentials[$key];
            if (contains($key, 'password')) {
                continue;
            }

            if (Array.isArray($value) || $value instanceof Array) {
                $query.whereIn($key, $value);
            } else {
                $query.where($key, $value);
            }
        }

        const $user = await $query.first();

        return this.getGenericUser($user);
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
     * Convert raw database record to GenericUser instance.
     *
     * @param $user - Database record or null
     * @returns GenericUser instance or undefined
     */
    public getGenericUser($user: Record<string, any> | null): GenericUser | undefined {
        if (!is_null($user)) {
            return new GenericUser($user);
        }
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param $user - User instance
     * @param $credentials - User credentials
     * @returns True if password matches
     */
    public validateCredentials($user: Record<string, any>, $credentials: Record<string, any> = {}): boolean {
        return this.$hasher.check(
            $credentials['password'],
            $user.getAuthPassword()
        );
    }
}

export default DatabaseUserProvider;