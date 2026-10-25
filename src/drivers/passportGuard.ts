import GuardHelpers from '../guardHelpers';
import { is_null, empty } from '@ostro/support/function';

export interface PassportOptions {
    provider?: any;
    tokenRepository?: any;
    clientRepository?: any;
    inputKey?: string;
    hash?: boolean;
}

export interface ClientCredentials {
    id: string | number;
    secret: string;
    name?: string;
}

/**
 * Class PassportGuard.
 *
 * Implements token & OAuth client credential authorization guard (similar to Laravel Passport).
 */
class PassportGuard extends GuardHelpers {
    public $request: any;
    declare public $provider: any;
    public $tokenRepository?: any;
    public $clientRepository?: any;
    public $inputKey: string = 'access_token';
    public $client: any = null;
    public $lastAttempted: any = null;

    /**
     * Create a new Passport guard instance.
     *
     * @param $provider - User provider instance
     * @param $request - Current HTTP request
     * @param options - Passport options including repositories
     */
    constructor($provider: any, $request: any, options: PassportOptions = {}) {
        super();
        this.$provider = $provider;
        this.$request = $request;
        this.$tokenRepository = options.tokenRepository;
        this.$clientRepository = options.clientRepository;
        if (options.inputKey) {
            this.$inputKey = options.inputKey;
        }
    }

    /**
     * Extract token string from Bearer header or input parameter.
     *
     * @returns Bearer token or null
     */
    public getTokenForRequest(): string | null {
        if (typeof this.$request?.bearerToken === 'function') {
            const bearer = this.$request.bearerToken();
            if (bearer) return bearer;
        }

        const authHeader = typeof this.$request?.header === 'function' ? this.$request.header('authorization') : null;
        if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
            return authHeader.slice(7).trim();
        }

        if (typeof this.$request?.input === 'function') {
            const val = this.$request.input(this.$inputKey);
            if (val) return String(val);
        }

        if (this.$request?.query && this.$request.query[this.$inputKey]) {
            return String(this.$request.query[this.$inputKey]);
        }

        return null;
    }

    /**
     * Get the currently authenticated user from access token.
     *
     * @returns Authenticated user or null
     */
    public async user(): Promise<any> {
        if (!is_null(this.$user)) {
            return this.$user;
        }

        const token = this.getTokenForRequest();
        if (empty(token)) {
            return null;
        }

        // 1. If tokenRepository is provided, resolve token record
        if (this.$tokenRepository && typeof this.$tokenRepository.findToken === 'function') {
            const tokenRecord = await this.$tokenRepository.findToken(token);
            if (!tokenRecord || (tokenRecord.revoked === true) || (tokenRecord.expires_at && new Date(tokenRecord.expires_at).getTime() < Date.now())) {
                return null;
            }

            if (tokenRecord.user_id && this.$provider) {
                const user = await this.$provider.retrieveById(tokenRecord.user_id);
                return (this.$user = user || null);
            }
        }

        // 2. Fallback direct token lookup via user provider
        if (this.$provider && typeof this.$provider.retrieveByCredentials === 'function') {
            const user = await this.$provider.retrieveByCredentials({
                api_token: token
            });
            if (user) {
                return (this.$user = user);
            }
        }

        return null;
    }

    /**
     * Authenticate OAuth client credentials directly.
     *
     * @param clientId - Client ID
     * @param clientSecret - Client Secret
     * @returns Authenticated client or null
     */
    public async authenticateClient(clientId: string | number, clientSecret: string): Promise<any> {
        if (this.$clientRepository && typeof this.$clientRepository.findClient === 'function') {
            const client = await this.$clientRepository.findClient(clientId);
            if (client && client.secret === clientSecret) {
                return (this.$client = client);
            }
        }
        return null;
    }

    /**
     * Get authenticated OAuth client.
     */
    public get client(): any {
        return this.$client;
    }

    /**
     * Revoke / invalidate a passport access token in the repository or static storage.
     *
     * @param token - Token string
     * @returns True if revoked
     */
    public async revokeToken(token: string): Promise<boolean> {
        if (this.$tokenRepository && typeof this.$tokenRepository.revokeToken === 'function') {
            await this.$tokenRepository.revokeToken(token);
            return true;
        }
        return false;
    }

    /**
     * Log out the current user by revoking token and clearing cached user.
     *
     * @returns True if logged out
     */
    public async logout(): Promise<boolean> {
        const token = this.getTokenForRequest();
        if (token) {
            await this.revokeToken(token);
        }
        this.$user = null;
        this.$client = null;
        return true;
    }

    /**
     * Validate user credentials.
     *
     * @param credentials - User credentials
     * @returns True if valid
     */
    public async validate(credentials: Record<string, any> = {}): Promise<boolean> {
        const user = await this.$provider.retrieveByCredentials(credentials);
        return !is_null(user) && (await this.$provider.validateCredentials(user, credentials));
    }
}

export default PassportGuard;
