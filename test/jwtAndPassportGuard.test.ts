import { describe, test, expect } from '@jest/globals';
import JwtGuard from '../src/drivers/jwtGuard';
import PassportGuard from '../src/drivers/passportGuard';
import AuthManager from '../src/authManager';

describe('JwtGuard Driver', () => {
    const mockProvider = {
        retrieveById: async (id: any) => ({ id, name: 'JWT User', email: 'jwt@example.com' }),
        retrieveByCredentials: async (creds: any) => {
            if (creds.email === 'jwt@example.com' && creds.password === 'secret') {
                return { id: 101, name: 'JWT User', email: 'jwt@example.com' };
            }
            return null;
        },
        validateCredentials: async (_user: any, creds: any) => creds.password === 'secret'
    };

    test('sign and verifyToken returns valid claims', () => {
        const guard = new JwtGuard(mockProvider, {}, { secret: 'my-super-secret-key', issuer: 'ostro', audience: 'app' });
        const token = guard.sign({ sub: 101, role: 'admin' }, 3600);
        expect(typeof token).toBe('string');

        const payload = guard.verifyToken(token);
        expect(payload).not.toBeNull();
        expect(payload?.sub).toBe(101);
        expect(payload?.role).toBe('admin');
        expect(payload?.iss).toBe('ostro');
        expect(payload?.aud).toBe('app');
    });

    test('verifyToken fails on expired or tampered token', () => {
        const guard = new JwtGuard(mockProvider, {}, { secret: 'my-super-secret-key' });
        const expiredToken = guard.sign({ sub: 101 }, -10);
        expect(guard.verifyToken(expiredToken)).toBeNull();

        const validToken = guard.sign({ sub: 101 }, 3600);
        const tampered = validToken.slice(0, -4) + 'abcd';
        expect(guard.verifyToken(tampered)).toBeNull();
        expect(guard.verifyToken('invalid.token')).toBeNull();
    });

    test('user() resolves user from Authorization Bearer header', async () => {
        const guard = new JwtGuard(mockProvider, {}, { secret: 'jwt-key' });
        const token = guard.sign({ sub: 101 });

        const reqWithBearer = {
            bearerToken: () => token
        };
        const activeGuard = new JwtGuard(mockProvider, reqWithBearer, { secret: 'jwt-key' });
        const user = await activeGuard.user();
        expect(user).not.toBeNull();
        expect(user.id).toBe(101);
        expect(await activeGuard.check()).toBe(true);
        expect(await activeGuard.guest()).toBe(false);
    });

    test('user() resolves user from query parameter or input', async () => {
        const guard = new JwtGuard(mockProvider, {}, { secret: 'jwt-key', inputKey: 'token' });
        const token = guard.sign({ sub: 101 });

        const reqWithQuery = {
            query: { token }
        };
        const activeGuard = new JwtGuard(mockProvider, reqWithQuery, { secret: 'jwt-key', inputKey: 'token' });
        const user = await activeGuard.user();
        expect(user.id).toBe(101);
    });

    test('attempt() authenticates valid credentials and returns token', async () => {
        const guard = new JwtGuard(mockProvider, {}, { secret: 'jwt-key' });
        const token = await guard.attempt({ email: 'jwt@example.com', password: 'secret' });
        expect(typeof token).toBe('string');
        const invalid = await guard.attempt({ email: 'jwt@example.com', password: 'wrong' });
        expect(invalid).toBeNull();
    });

    test('validate() checks credentials without creating session', async () => {
        const guard = new JwtGuard(mockProvider, {}, { secret: 'jwt-key' });
        expect(await guard.validate({ email: 'jwt@example.com', password: 'secret' })).toBe(true);
        expect(await guard.validate({ email: 'jwt@example.com', password: 'wrong' })).toBe(false);
    });
});

describe('PassportGuard Driver', () => {
    const mockTokenRepo = {
        findToken: async (token: string) => {
            if (token === 'valid-oauth-token') {
                return { id: 1, user_id: 202, revoked: false, expires_at: new Date(Date.now() + 60000) };
            }
            if (token === 'revoked-token') {
                return { id: 2, user_id: 202, revoked: true };
            }
            if (token === 'expired-token') {
                return { id: 3, user_id: 202, revoked: false, expires_at: new Date(Date.now() - 60000) };
            }
            return null;
        }
    };

    const mockClientRepo = {
        findClient: async (id: any) => {
            if (id === 'app-client-1') {
                return { id: 'app-client-1', secret: 'client-secret-xyz', name: 'Mobile App' };
            }
            return null;
        }
    };

    const mockProvider = {
        retrieveById: async (id: any) => ({ id, name: 'OAuth User' }),
        retrieveByCredentials: async (creds: any) => {
            if (creds.api_token === 'fallback-token') {
                return { id: 303, name: 'Fallback User' };
            }
            return null;
        },
        validateCredentials: async (_user: any, creds: any) => creds.password === 'pass'
    };

    test('authenticates user via token repository', async () => {
        const req = {
            header: (k: string) => k === 'authorization' ? 'Bearer valid-oauth-token' : null
        };
        const guard = new PassportGuard(mockProvider, req, {
            tokenRepository: mockTokenRepo,
            clientRepository: mockClientRepo
        });

        const user = await guard.user();
        expect(user).not.toBeNull();
        expect(user.id).toBe(202);
    });

    test('rejects revoked or expired token', async () => {
        const revokedReq = { bearerToken: () => 'revoked-token' };
        const revokedGuard = new PassportGuard(mockProvider, revokedReq, { tokenRepository: mockTokenRepo });
        expect(await revokedGuard.user()).toBeNull();

        const expiredReq = { bearerToken: () => 'expired-token' };
        const expiredGuard = new PassportGuard(mockProvider, expiredReq, { tokenRepository: mockTokenRepo });
        expect(await expiredGuard.user()).toBeNull();
    });

    test('authenticates OAuth client credentials directly', async () => {
        const guard = new PassportGuard(mockProvider, {}, {
            clientRepository: mockClientRepo
        });
        const client = await guard.authenticateClient('app-client-1', 'client-secret-xyz');
        expect(client).not.toBeNull();
        expect(client.name).toBe('Mobile App');
        expect(guard.client).toBe(client);

        const invalid = await guard.authenticateClient('app-client-1', 'wrong-secret');
        expect(invalid).toBeNull();
    });

    test('AuthManager resolves createJwtDriver and createPassportDriver', () => {
        const app: any = {
            config: {
                get: (k: string) => {
                    if (k === 'auth.guards.jwt') {
                        return { driver: 'jwt', provider: 'users', secret: 'my-secret' };
                    }
                    if (k === 'auth.guards.passport') {
                        return { driver: 'passport', provider: 'users' };
                    }
                    return null;
                }
            }
        };

        const auth = new AuthManager(app);
        auth.provider('users', () => mockProvider);
        const jwtFactory = auth.createJwtDriver({ provider: 'users', secret: 'test-secret' }, 'jwt');
        const passportFactory = auth.createPassportDriver({ provider: 'users' }, 'passport');

        expect(typeof jwtFactory).toBe('function');
        expect(typeof passportFactory).toBe('function');

        const jwtGuardInst = jwtFactory({});
        const passportGuardInst = passportFactory({});

        expect(jwtGuardInst instanceof JwtGuard).toBe(true);
        expect(passportGuardInst instanceof PassportGuard).toBe(true);
    });

    test('JwtGuard logout blacklists token and clears user', async () => {
        const req = {
            bearerToken: () => 'token-to-logout'
        };
        const guard = new JwtGuard(mockProvider, req, { secret: 'secret' });
        const token = guard.sign({ sub: 100 });
        req.bearerToken = () => token;

        expect(guard.isTokenBlacklisted(token)).toBe(false);
        const loggedOut = await guard.logout();
        expect(loggedOut).toBe(true);
        expect(guard.isTokenBlacklisted(token)).toBe(true);
        expect(guard.verifyToken(token)).toBeNull();
        expect(await guard.user()).toBeNull();
    });

    test('PassportGuard logout revokes token and clears client and user', async () => {
        const revokedTokens = new Set<string>();
        const repo = {
            findToken: async (t: string) => ({ token: t, user_id: 1, revoked: revokedTokens.has(t) }),
            revokeToken: async (t: string) => { revokedTokens.add(t); }
        };
        const req = {
            bearerToken: () => 'oauth-token-123'
        };
        const guard = new PassportGuard(mockProvider, req, { tokenRepository: repo });
        const user = await guard.user();
        expect(user).not.toBeNull();

        const loggedOut = await guard.logout();
        expect(loggedOut).toBe(true);
        expect(revokedTokens.has('oauth-token-123')).toBe(true);
        expect(await guard.user()).toBeNull();
    });

    test('MemoryTokenRepository and MemoryClientRepository work out-of-the-box', async () => {
        const guard = new PassportGuard(mockProvider, {});
        const tokenRepo = guard.getTokenRepository();
        const clientRepo = guard.getClientRepository();

        expect(tokenRepo).toBeDefined();
        expect(clientRepo).toBeDefined();

        // Create token
        const createdToken = await tokenRepo.createToken(55, 'mem-token-xyz', 'client-app', 3600);
        expect(createdToken.token).toBe('mem-token-xyz');
        expect(createdToken.user_id).toBe(55);
        expect(createdToken.revoked).toBe(false);

        // Find token
        const found = await tokenRepo.findToken('mem-token-xyz');
        expect(found?.user_id).toBe(55);

        // Check isRevoked
        expect(await tokenRepo.isRevoked('mem-token-xyz')).toBe(false);
        expect(await tokenRepo.isRevoked('non-existent')).toBe(true);

        // Revoke token
        expect(await tokenRepo.revokeToken('mem-token-xyz')).toBe(true);
        expect(await tokenRepo.revokeToken('non-existent')).toBe(false);
        expect(await tokenRepo.isRevoked('mem-token-xyz')).toBe(true);

        // Client repo
        await clientRepo.createClient('app-1', 'sec-1', 'App One');
        const client = await clientRepo.findClient('app-1');
        expect(client?.name).toBe('App One');
        expect(await clientRepo.findClient('app-none')).toBeNull();

        // Check clear
        tokenRepo.clear();
        expect(await tokenRepo.findToken('mem-token-xyz')).toBeNull();
        clientRepo.clear();
        expect(await clientRepo.findClient('app-1')).toBeNull();

        // Test setters
        const newRepo = { findToken: () => null };
        guard.setTokenRepository(newRepo);
        expect(guard.getTokenRepository()).toBe(newRepo);

        const newClientRepo = { findClient: () => null };
        guard.setClientRepository(newClientRepo);
        expect(guard.getClientRepository()).toBe(newClientRepo);
    });

    test('AuthManager resolves repositories via string container binding or class constructor', () => {
        class CustomTokenRepo {
            public isCustom = true;
        }

        const app: any = {
            make: (key: string) => {
                if (key === 'custom.client.repo') {
                    return { isCustomClient: true };
                }
                return null;
            },
            config: {
                get: (k: string) => null
            }
        };

        const auth = new AuthManager(app);
        auth.provider('users', () => mockProvider);

        const factory = auth.createPassportDriver({
            provider: 'users',
            token_repository: CustomTokenRepo,
            client_repository: 'custom.client.repo'
        }, 'passport');

        const guard = factory({});
        expect(guard.getTokenRepository().isCustom).toBe(true);
        expect(guard.getClientRepository().isCustomClient).toBe(true);

        // Test function factory repo
        const factory2 = auth.createPassportDriver({
            provider: 'users',
            token_repository: ($app: any) => ({ factoryInst: true })
        }, 'passport');
        const guard2 = factory2({});
        expect(guard2.getTokenRepository().factoryInst).toBe(true);
    });
});
