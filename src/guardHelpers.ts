import AuthenticationException from './authenticationException';
import { is_null } from '@ostro/support/function';

/**
 * Class GuardHelpers.
 */
abstract class GuardHelpers {
    public $user: any = null;

    public $provider: any;

    /**
     * Get the currently authenticated user.
     */
    abstract user(): Promise<any>;

    /**
     * Determine if the current user is authenticated. If not, throw an exception.
     *
     * @returns The authenticated user
     * @throws AuthenticationException
     */
    public async authenticate(): Promise<any> {
        const $user = await this.user();
        if (!is_null($user)) {
            return $user;
        }

        throw new AuthenticationException();
    }

    /**
     * Determine if the guard has a user instance.
     *
     * @returns True if a user is set
     */
    public hasUser(): boolean {
        return !is_null(this.$user);
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @returns True if user is authenticated
     */
    public async check(): Promise<boolean> {
        return !is_null(await this.user());
    }

    /**
     * Determine if the current user is a guest.
     *
     * @returns True if user is not authenticated
     */
    public async guest(): Promise<boolean> {
        return !(await this.check());
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @returns The user's auth identifier or undefined
     */
    public async id(): Promise<any> {
        const user = await this.user();
        if (user) {
            return user.getAuthIdentifier();
        }
    }

    /**
     * Set the current user.
     *
     * @param $user - User instance or null
     * @returns Current guard instance
     */
    public setUser($user: any): this {
        this.$user = $user;

        return this;
    }

    /**
     * Get the user provider used by the guard.
     *
     * @returns The user provider instance
     */
    public getProvider(): any {
        return this.$provider;
    }

    /**
     * Set the user provider used by the guard.
     *
     * @param $provider - User provider instance
     */
    public setProvider($provider: any): void {
        this.$provider = $provider;
    }
}

export default GuardHelpers;