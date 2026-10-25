import GuardHelpers from './guardHelpers';
import { createHash } from 'node:crypto';
import { is_null, empty } from '@ostro/support/function';

/**
 * Class TokenGuard.
 */
class TokenGuard extends GuardHelpers {
    public $hash: boolean;
    public $request: any;
    declare public $provider: any;
    public $inputKey: string = 'api_token';
    public $storageKey: string = 'api_token';
    public $lastAttempted: any;

    /**
     * Create a new token guard instance.
     *
     * @param $provider - User provider instance
     * @param $request - Request instance
     * @param $inputKey - Token input key name
     * @param $storageKey - Storage column key name
     * @param $hash - Whether tokens are hashed
     */
    constructor(
        $provider: any,
        $request: any,
        $inputKey: string = 'api_token',
        $storageKey: string = 'api_token',
        $hash: boolean = false
    ) {
        super();
        this.$hash = $hash;
        this.$request = $request;
        this.$provider = $provider;
        this.$inputKey = $inputKey;
        this.$storageKey = $storageKey;
    }

    /**
     * Determine if the user matches credentials.
     *
     * @param $user - User instance
     * @param $credentials - User credentials
     * @returns True if valid credentials
     */
    public async hasValidCredentials($user: any, $credentials: Record<string, any>): Promise<boolean> {
        return !is_null($user) && (await this.$provider.validateCredentials($user, $credentials));
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param $credentials - User credentials
     * @returns True if authentication succeeded
     */
    public async attempt($credentials: Record<string, any> = {}): Promise<boolean> {
        const $user = await this.$provider.retrieveByCredentials($credentials);
        this.$lastAttempted = $user;

        if (await this.hasValidCredentials($user, $credentials)) {
            this.$user = $user;
            await this.user();

            return true;
        }

        return false;
    }

    /**
     * Get the currently authenticated user.
     *
     * @returns Authenticated user or null
     */
    public async user(): Promise<any> {
        if (!is_null(this.$user)) {
            return this.$user;
        }

        let $user = null;

        const $token = this.getTokenForRequest();
        if (!empty($token)) {
            $user = await this.$provider.retrieveByCredentials({
                [this.$storageKey]: this.$hash ? createHash('sha256').update($token).digest('hex') : $token,
            });
        }

        return (this.$user = $user);
    }

    /**
     * Get the token for the current request.
     *
     * @returns Token string or null
     */
    public getTokenForRequest(): string | null | undefined {
        let $token = this.$request.getQuery(this.$inputKey);
        if (empty($token)) {
            $token = this.$request.input(this.$inputKey);
        }

        if (empty($token)) {
            $token = this.$request.bearerToken();
        }

        if (empty($token)) {
            $token = this.$request.getPassword();
        }

        return $token;
    }

    /**
     * Validate a user's credentials.
     *
     * @param $credentials - User credentials
     * @returns True if credentials are valid
     */
    public async validate($credentials: Record<string, any> = {}): Promise<boolean> {
        if (empty($credentials[this.$inputKey])) {
            return false;
        }

        const creds = {
            [this.$storageKey]: $credentials[this.$inputKey],
        };

        if (await this.$provider.retrieveByCredentials(creds)) {
            return true;
        }

        return false;
    }
}

export default TokenGuard;