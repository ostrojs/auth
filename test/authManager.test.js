require('@ostro/support/helpers');
const AuthManager = require('../authManager');
const AuthRequest = require('../authRequest');
const AuthServiceProvider = require('../authServiceProvider');

describe('AuthManager & AuthRequest Unit Tests', () => {
    let mockApp;

    beforeEach(() => {
        const mockConfig = {
            auth: {
                defaults: { guard: 'web' },
                guards: {
                    web: { driver: 'session', provider: 'users' },
                    api: { driver: 'token', provider: 'users', input_key: 'api_token' }
                },
                providers: {
                    users: { driver: 'database', table: 'users' }
                }
            }
        };
        mockApp = {
            config: {
                get: jest.fn().mockImplementation((key) => {
                    const dict = {
                        'auth.defaults.guard': 'web',
                        'auth.defaults.provider': 'users',
                        'auth.guards.web': { driver: 'session', provider: 'users' },
                        'auth.guards.api': { driver: 'token', provider: 'users', input_key: 'api_token' },
                        'auth.providers.users': { driver: 'database', table: 'users' },
                        'auth.providers.eloquent_test': { driver: 'eloquent', model: class MockModel {} },
                        'auth.providers.custom': { driver: 'custom_driver' },
                        'auth.providers.unknown': { driver: 'unknown_driver' },
                        'auth.providers.no_driver': { table: 'users' }
                    };
                    return dict[key];
                })
            },
            make: jest.fn().mockImplementation((key) => {
                if (key === 'config') return mockConfig;
                return null;
            }),
            singleton: jest.fn(),
            bind: jest.fn(),
            rebinding: jest.fn()
        };
    });

    test('getDefaultDriver returns default guard from config', () => {
        mockApp.db = { connection: jest.fn() };
        const manager = new AuthManager(mockApp);
        expect(manager.getDefaultDriver()).toBe('web');
        expect(manager.createSessionDriver({}, 'web')).toBeDefined();
        expect(manager.createTokenDriver({}, 'api')).toBeDefined();
    });

    test('userResolver getter and setter', () => {
        const manager = new AuthManager(mockApp);
        const customResolver = () => ({ id: 99 });

        manager.resolveUsersUsing(customResolver);
        expect(manager.userResolver()).toBe(customResolver);
    });

    test('AuthRequest delegates guard resolution and default driver changes', async () => {
        const mockGuardInstance = { user: jest.fn().mockResolvedValue({ id: 1 }) };
        const mockManager = {
            getDefaultDriver: jest.fn().mockReturnValue('web'),
            guard: jest.fn().mockReturnValue(jest.fn().mockReturnValue(mockGuardInstance))
        };
        const mockRequest = {};

        const authReq = new AuthRequest(mockRequest, mockManager);
        const guard = authReq.guard();

        expect(mockManager.guard).toHaveBeenCalledWith('web');
        expect(guard).toBe(mockGuardInstance);

        const user = await authReq.shouldUse('api');
        expect(user).toEqual({ id: 1 });

        // Test shouldUse with default guard
        const userDefault = await authReq.shouldUse();
        expect(userDefault).toEqual({ id: 1 });

        authReq.setDefaultDriverForCurrentRequest('custom');
        expect(authReq.$defaultGuard).toBe('custom');

        // Test magic method invocation via __get
        expect(authReq.user).toBeDefined();
    });

    test('createUserProvider resolves database provider', () => {
        mockApp.db = { connection: jest.fn().mockReturnValue({}) };
        mockApp.hash = {};
        const manager = new AuthManager(mockApp);

        const provider = manager.createUserProvider('users');
        expect(provider).toBeDefined();
        expect(mockApp.db.connection).toHaveBeenCalled();
    });

    test('createUserProvider resolves custom provider callback', () => {
        const manager = new AuthManager(mockApp);
        const customCallback = jest.fn().mockReturnValue({ custom: true });
        manager.provider('custom_driver', customCallback);

        mockApp.make('config').auth.providers.custom = { driver: 'custom_driver' };
        const provider = manager.createUserProvider('custom');

        expect(provider).toEqual({ custom: true });
        expect(customCallback).toHaveBeenCalled();
    });

    test('createUserProvider resolves eloquent provider and handles missing configs', () => {
        mockApp.hash = {};
        const manager = new AuthManager(mockApp);

        const provider = manager.createUserProvider('eloquent_test');
        expect(provider).toBeDefined();

        expect(manager.createUserProvider('non_existent_provider')).toBeUndefined();
    });

    test('createUserProvider throws InvalidArgumentException for unknown driver or missing driver', () => {
        const InvalidArgumentException = require('@ostro/support/exceptions/invalidArgumentException');
        const manager = new AuthManager(mockApp);
        mockApp.make('config').auth.providers.unknown = { driver: 'unknown_driver' };
        mockApp.make('config').auth.providers.no_driver = { table: 'users' };

        expect(() => manager.createUserProvider('unknown')).toThrow(InvalidArgumentException);
        expect(() => manager.createUserProvider('no_driver')).toThrow(InvalidArgumentException);
    });

    test('createSessionDriver and createTokenDriver factory functions', () => {
        mockApp.db = { connection: jest.fn().mockReturnValue({}) };
        mockApp.hash = {};
        const manager = new AuthManager(mockApp);

        const sessionFactory = manager.createSessionDriver({ provider: 'users' }, 'web');
        const sessionGuard = sessionFactory({ session: {}, cookie: {} });
        expect(sessionGuard).toBeDefined();

        const tokenFactory = manager.createTokenDriver({ provider: 'users' }, 'api');
        const tokenGuard = tokenFactory({});
        expect(tokenGuard).toBeDefined();
    });

    test('AuthManager guard() and resolve() handle default and custom drivers', () => {
        mockApp.db = { connection: jest.fn().mockReturnValue({}) };
        mockApp.hash = {};
        const manager = new AuthManager(mockApp);

        expect(() => manager.guard('nonexistent_guard')).toThrow();

        const sessionGuardFactory = manager.guard('web');
        expect(typeof sessionGuardFactory).toBe('function');
    });

    test('AuthManager $userResolver and req.user() callback execution', async () => {
        mockApp.db = { connection: jest.fn().mockReturnValue({}) };
        mockApp.hash = {};
        const manager = new AuthManager(mockApp);

        const mockGuardInstance = { user: jest.fn().mockResolvedValue({ id: 5 }) };
        jest.spyOn(manager, 'guard').mockReturnValue(mockGuardInstance);

        const userResolver = manager.userResolver();
        const resolvedUser = await userResolver.call(manager, 'web');
        expect(resolvedUser).toEqual({ id: 5 });

        // Test req.user() attached by start()
        const req = {};
        const next = jest.fn();
        manager.start()(req, {}, next);
        expect(req.auth).toBeInstanceOf(AuthRequest);
        expect(typeof req.user).toBe('function');
        expect(next).toHaveBeenCalled();

        req.auth = { guard: jest.fn().mockReturnValue(mockGuardInstance) };
        const reqUser = await req.user('web');
        expect(reqUser).toEqual({ id: 5 });
    });

    test('createUserProvider falls back to default provider when none specified', () => {
        mockApp.db = { connection: jest.fn().mockReturnValue({}) };
        mockApp.hash = {};
        const manager = new AuthManager(mockApp);

        const provider = manager.createUserProvider();
        expect(provider).toBeDefined();
    });

    test('hasResolvedGuards and forgetGuards check resolved driver state', () => {
        mockApp.db = { connection: jest.fn().mockReturnValue({}) };
        mockApp.hash = {};
        const manager = new AuthManager(mockApp);
        expect(manager.hasResolvedGuards()).toBe(false);

        manager.$drivers = { web: {} };
        expect(manager.hasResolvedGuards()).toBe(true);

        manager.forgetGuards();
        expect(manager.hasResolvedGuards()).toBe(false);
    });

    test('AuthServiceProvider registers singletons and user resolver bindings', () => {
        const provider = new AuthServiceProvider(mockApp);
        provider.register();
        provider.boot();
        provider.registerUserResolver();
        provider.registerRequestRebindHandler();

        expect(mockApp.singleton).toHaveBeenCalledWith('auth', expect.any(Function));
        expect(mockApp.singleton).toHaveBeenCalledWith('auth.driver', expect.any(Function));
        expect(mockApp.bind).toHaveBeenCalledWith('@ostro/contracts/auth/authenticatable', expect.any(Function));
        expect(mockApp.rebinding).toHaveBeenCalledWith('request', expect.any(Function));

        // Invoke registered callbacks to verify coverage of closure bodies
        const authCallback = mockApp.singleton.mock.calls.find(c => c[0] === 'auth')[1];
        expect(authCallback(mockApp)).toBeInstanceOf(AuthManager);

        const mockAuthInstance = { guard: jest.fn().mockReturnValue({}), userResolver: jest.fn().mockReturnValue(jest.fn().mockReturnValue({ id: 1 })) };
        mockApp['auth'] = mockAuthInstance;

        const driverCallback = mockApp.singleton.mock.calls.find(c => c[0] === 'auth.driver')[1];
        expect(driverCallback(mockApp)).toBeDefined();

        const userResolverCallback = mockApp.bind.mock.calls.find(c => c[0] === '@ostro/contracts/auth/authenticatable')[1];
        expect(userResolverCallback(mockApp)).toEqual({ id: 1 });

        const rebindCallback = mockApp.rebinding.mock.calls.find(c => c[0] === 'request')[1];
        const mockRequestInstance = { setUserResolver: jest.fn() };
        rebindCallback(mockApp, mockRequestInstance);
        expect(mockRequestInstance.setUserResolver).toHaveBeenCalledWith(expect.any(Function));

        const setUserResolverFn = mockRequestInstance.setUserResolver.mock.calls[0][0];
        expect(setUserResolverFn('web')).toEqual({ id: 1 });
    });
});
