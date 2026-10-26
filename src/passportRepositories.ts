export interface OAuthToken {
    token: string;
    user_id: number | string;
    client_id?: string | number;
    revoked?: boolean;
    expires_at?: Date | string | number;
    created_at?: Date | string | number;
    [key: string]: any;
}

export interface OAuthClient {
    id: string | number;
    secret: string;
    name?: string;
    [key: string]: any;
}

export interface ITokenRepository {
    findToken(token: string): Promise<OAuthToken | null> | OAuthToken | null;
    createToken?(userId: number | string, tokenString: string, clientId?: string | number, expiresInSeconds?: number): Promise<OAuthToken> | OAuthToken;
    revokeToken?(token: string): Promise<boolean | void> | boolean | void;
    isRevoked?(token: string): Promise<boolean> | boolean;
}

export interface IClientRepository {
    findClient(id: string | number): Promise<OAuthClient | null> | OAuthClient | null;
    createClient?(id: string | number, secret: string, name?: string): Promise<OAuthClient> | OAuthClient;
}

export class MemoryTokenRepository implements ITokenRepository {
    protected tokens: Map<string, OAuthToken> = new Map<string, OAuthToken>();

    public async findToken(token: string): Promise<OAuthToken | null> {
        return this.tokens.get(token) || null;
    }

    public async createToken(userId: number | string, tokenString: string, clientId?: string | number, expiresInSeconds: number = 3600): Promise<OAuthToken> {
        const record: OAuthToken = {
            token: tokenString,
            user_id: userId,
            client_id: clientId,
            revoked: false,
            expires_at: new Date(Date.now() + expiresInSeconds * 1000),
            created_at: new Date()
        };
        this.tokens.set(tokenString, record);
        return record;
    }

    public async revokeToken(token: string): Promise<boolean> {
        const record = this.tokens.get(token);
        if (record) {
            record.revoked = true;
            return true;
        }
        return false;
    }

    public async isRevoked(token: string): Promise<boolean> {
        const record = this.tokens.get(token);
        return !record || record.revoked === true;
    }

    public clear(): void {
        this.tokens.clear();
    }
}

export class MemoryClientRepository implements IClientRepository {
    protected clients: Map<string | number, OAuthClient> = new Map<string | number, OAuthClient>();

    constructor(initialClients?: OAuthClient[]) {
        if (Array.isArray(initialClients)) {
            for (const client of initialClients) {
                this.clients.set(client.id, client);
            }
        }
    }

    public async findClient(id: string | number): Promise<OAuthClient | null> {
        return this.clients.get(id) || null;
    }

    public async createClient(id: string | number, secret: string, name?: string): Promise<OAuthClient> {
        const client: OAuthClient = { id, secret, name };
        this.clients.set(id, client);
        return client;
    }

    public clear(): void {
        this.clients.clear();
    }
}
