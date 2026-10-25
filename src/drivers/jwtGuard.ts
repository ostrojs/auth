import GuardHelpers from '../guardHelpers';
import { is_null, empty } from '@ostro/support/function';
import { createHmac, randomUUID } from 'node:crypto';

export interface JwtOptions {
    secret: string;
    algorithm?: string;
    issuer?: string;
    audience?: string;
    inputKey?: string;
}

export interface JwtPayload {
    sub?: string | number;
    iss?: string;
    aud?: string;
    exp?: number;
    nbf?: number;
    iat?: number;
    [key: string]: unknown;
}

/**
 * Class JwtGuard.
 *
 * Implements standard stateless JSON Web Token (JWT) guard.
 */
class JwtGuard extends GuardHelpers {
    public $secret: string;
    public $request: any;
    declare public $provider: any;
    public $inputKey: string;
    public $algorithm: string;
    public $issuer?: string;
    public $audience?: string;
    public $lastAttempted: any = null;

    /**
     * Create a new JWT guard instance.
     *
     * @param $provider - User provider instance
     * @param $request - Current HTTP request
     * @param options - Configuration options (secret, inputKey, etc.)
     */
    constructor($provider: any, $request: any, options: JwtOptions) {
        super();
        this.$provider = $provider;
        this.$request = $request;
        this.$secret = options.secret;
        this.$algorithm = options.algorithm || 'HS256';
        this.$inputKey = options.inputKey || 'token';
        this.$issuer = options.issuer;
        this.$audience = options.audience;
    }

    /**
     * Get the token for the current request.
     * Checks bearer token, query parameters, or form body inputs.
     *
     * @returns Token string or null
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
     * Decode and verify a JWT signature and timing claims.
     *
     * @param token - Compact JWT string (header.payload.signature)
     * @returns Decoded payload or null if invalid/expired
     */
    public verifyToken(token: string): JwtPayload | null {
        try {
            if (this.isTokenBlacklisted(token)) {
                return null;
            }
            const parts = token.split('.');
            if (parts.length !== 3) return null;

            const [headerB64, payloadB64, signatureB64] = parts;
            const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
            if (header.alg !== 'HS256' && this.$algorithm === 'HS256') {
                return null;
            }

            const expectedSig = createHmac('sha256', this.$secret)
                .update(`${headerB64}.${payloadB64}`)
                .digest('base64url');

            if (expectedSig !== signatureB64) {
                return null;
            }

            const payload: JwtPayload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
            const now = Math.floor(Date.now() / 1000);

            if (payload.exp !== undefined && payload.exp < now) {
                return null;
            }

            if (payload.nbf !== undefined && payload.nbf > now) {
                return null;
            }

            if (this.$issuer && payload.iss !== this.$issuer) {
                return null;
            }

            if (this.$audience && payload.aud !== this.$audience) {
                return null;
            }

            return payload;
        } catch {
            return null;
        }
    }

    /**
     * Generate / sign a JWT token for a payload.
     *
     * @param payload - Payload object with claims
     * @param expiresInSeconds - Token lifetime in seconds
     * @returns Compact signed JWT string
     */
    public sign(payload: JwtPayload, expiresInSeconds: number = 3600): string {
        const header = { alg: this.$algorithm, typ: 'JWT' };
        const now = Math.floor(Date.now() / 1000);
        const claims: JwtPayload = {
            iat: now,
            exp: now + expiresInSeconds,
            ...(this.$issuer ? { iss: this.$issuer } : {}),
            ...(this.$audience ? { aud: this.$audience } : {}),
            ...payload
        };

        const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
        const payloadB64 = Buffer.from(JSON.stringify(claims)).toString('base64url');
        const signatureB64 = createHmac('sha256', this.$secret)
            .update(`${headerB64}.${payloadB64}`)
            .digest('base64url');

        return `${headerB64}.${payloadB64}.${signatureB64}`;
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

        const token = this.getTokenForRequest();
        if (empty(token)) {
            return null;
        }

        const payload = this.verifyToken(token as string);
        if (!payload || !payload.sub) {
            return null;
        }

        const user = await this.$provider.retrieveById(payload.sub);
        return (this.$user = user || null);
    }

    /**
     * Validate user credentials and return signed token if successful.
     *
     * @param credentials - Credentials dictionary (e.g. email, password)
     * @returns Signed JWT string or null
     */
    public async attempt(credentials: Record<string, any> = {}): Promise<string | null> {
        const user = await this.$provider.retrieveByCredentials(credentials);
        this.$lastAttempted = user;

        if (user && (await this.$provider.validateCredentials(user, credentials))) {
            this.$user = user;
            const sub = typeof user.getAuthIdentifier === 'function' ? user.getAuthIdentifier() : (user.id || user._id);
            return this.sign({ sub, email: user.email, name: user.name, jti: randomUUID() });
        }

        return null;
    }

    public static $blacklist: Set<string> = new Set<string>();

    /**
     * Invalidate/blacklist a token.
     *
     * @param token - Compact JWT string
     */
    public blacklistToken(token: string): void {
        JwtGuard.$blacklist.add(token);
    }

    /**
     * Check if a token has been blacklisted.
     *
     * @param token - Compact JWT string
     * @returns True if blacklisted
     */
    public isTokenBlacklisted(token: string): boolean {
        return JwtGuard.$blacklist.has(token);
    }

    /**
     * Log the user out by blacklisting the current request token and clearing user state.
     *
     * @returns True if token was blacklisted or user cleared
     */
    public async logout(): Promise<boolean> {
        const token = this.getTokenForRequest();
        if (token) {
            this.blacklistToken(token);
        }
        this.$user = null;
        return true;
    }

    /**
     * Validate credentials without establishing session state.
     *
     * @param credentials - User credentials
     * @returns True if credentials match
     */
    public async validate(credentials: Record<string, any> = {}): Promise<boolean> {
        const user = await this.$provider.retrieveByCredentials(credentials);
        return !is_null(user) && (await this.$provider.validateCredentials(user, credentials));
    }
}

export default JwtGuard;
