require('@ostro/support/helpers');
const SessionGuard = require('../sessionGuard');

describe('SessionGuard Multi-Scenario Coverage Tests', () => {
    let mockProvider;
    let mockSession;
    let mockCookie;
    let mockRequest;

    beforeEach(() => {
        mockProvider = {
            retrieveById: jest.fn(),
            retrieveByToken: jest.fn(),
            retrieveByCredentials: jest.fn(),
            validateCredentials: jest.fn(),
            updateRememberToken: jest.fn()
        };
        mockSession = {
            get: jest.fn(),
            put: jest.fn(),
            forget: jest.fn(),
            remove: jest.fn(),
            migrate: jest.fn()
        };
        mockCookie = {
            get: jest.fn(),
            queue: jest.fn(),
            forget: jest.fn(),
            forever: jest.fn()
        };
        mockRequest = {
            session: mockSession,
            cookie: mockCookie,
            getUser: jest.fn(),
            getPassword: jest.fn()
        };

        Object.setPrototypeOf(mockSession, require('@ostro/contracts/session/session').prototype);
    });

    test('getters & setters: getSession, getUser, getRequest, setRequest, setCookieJar', () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);

        expect(guard.getSession()).toBe(mockSession);
        expect(guard.getUser()).toBeNull();
        expect(guard.getRequest()).toBe(mockRequest);

        const newRequest = { session: {}, cookie: {} };
        guard.setRequest(newRequest);
        expect(guard.getRequest()).toBe(newRequest);

        const newCookie = {};
        guard.setCookieJar(newCookie);
        expect(guard.getCookieJar()).toBe(newCookie);
    });

    test('getCookieJar throws Error when cookie is null/undefined', () => {
        const guard = new SessionGuard('web', mockProvider, { session: mockSession });
        expect(() => guard.getCookieJar()).toThrow('Cookie jar has not been set.');
    });

    test('user() returns undefined when logged out or session is null', async () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        await guard.logout();
        expect(await guard.user()).toBeUndefined();

        const guardNoSession = new SessionGuard('web', mockProvider, { cookie: mockCookie });
        expect(await guardNoSession.user()).toBeUndefined();
    });

    test('attempt() and attemptWhen() return false when credentials validation fails', async () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        mockProvider.retrieveByCredentials.mockResolvedValue(null);

        expect(await guard.attempt({})).toBe(false);
        expect(await guard.attemptWhen({})).toBe(false);
    });

    test('basic() throws error when unauthenticated and returns when authenticated', async () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        mockRequest.getUser.mockReturnValue('user');
        mockRequest.getPassword.mockReturnValue('wrong_pass');
        mockProvider.retrieveByCredentials.mockResolvedValue(null);

        await expect(guard.basic()).rejects.toThrow();

        const fakeUser = { id: 1 };
        guard.setUser(fakeUser);
        expect(await guard.basic()).toBeUndefined();
    });

    test('userFromRecaller returns early for invalid token', async () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        expect(await guard.userFromRecaller({ valid: () => false })).toBeUndefined();
    });

    test('recaller returns Recaller instance when cookie jar is present', () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        guard.setCookieJar({ get: jest.fn().mockReturnValue('token|hash|id') });
        expect(guard.recaller()).toBeDefined();

        guard.setCookieJar(null);
        expect(guard.recaller()).toBeUndefined();
    });

    test('onceUsingId returns false when provider yields null', async () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        mockProvider.retrieveById.mockResolvedValueOnce(null);
        expect(await guard.onceUsingId(999)).toBe(false);
    });

    test('attemptBasic returns false when request user is empty', () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        mockRequest.getUser.mockReturnValue(null);
        expect(guard.attemptBasic(mockRequest, 'email')).toBe(false);
    });

    test('basic() executes attemptBasic successfully', async () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        mockSession.get.mockReturnValue(null);
        mockProvider.retrieveById.mockResolvedValue(null);
        mockRequest.getUser.mockReturnValue('user');
        mockRequest.getPassword.mockReturnValue('pass');
        const fakeUser = { id: 2, getAuthIdentifier: () => 2 };
        mockProvider.retrieveByCredentials.mockResolvedValue(fakeUser);
        mockProvider.validateCredentials.mockReturnValue(true);

        expect(await guard.basic()).toBeUndefined();
        expect(guard.getUser()).toBe(fakeUser);
    });

    test('onceBasic() handles success and failure paths', async () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        mockRequest.getUser.mockReturnValue('user');
        mockRequest.getPassword.mockReturnValue('pass');

        mockProvider.retrieveByCredentials.mockResolvedValueOnce(null);
        await expect(guard.onceBasic()).rejects.toThrow();

        const fakeUser = { id: 10 };
        mockProvider.retrieveByCredentials.mockResolvedValueOnce(fakeUser);
        mockProvider.validateCredentials.mockReturnValue(true);
        await guard.onceBasic();
        expect(guard.getUser()).toBe(fakeUser);
    });

    test('user() restores user via recaller cookie when session user is null', async () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        mockSession.get.mockReturnValue(null);
        mockCookie.get.mockReturnValue('10|remember_token_hash|pass_hash');

        const fakeUser = {
            getAuthIdentifier: () => 10,
            getRememberToken: () => 'remember_token_hash'
        };
        mockProvider.retrieveByToken.mockResolvedValue(fakeUser);

        const user = await guard.user();
        expect(user).toBe(fakeUser);
        expect(guard.viaRemember()).toBe(true);
    });

    test('id() returns user auth identifier or session id', async () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        mockSession.get.mockReturnValue(88);
        expect(await guard.id()).toBe(88);

        const fakeUser = {
            getAuthIdentifier: () => 99,
            getRememberToken: () => null
        };
        guard.setUser(fakeUser);
        expect(await guard.id()).toBe(99);

        await guard.logout();
        expect(await guard.id()).toBeUndefined();
    });

    test('attempt(), attemptWhen(), once(), onceUsingId() operations', async () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        const fakeUser = {
            getAuthIdentifier: () => 55,
            getRememberToken: () => '',
            setRememberToken: jest.fn(),
            getAuthPassword: () => 'hashed_pass'
        };

        mockProvider.retrieveByCredentials.mockResolvedValue(fakeUser);
        mockProvider.validateCredentials.mockResolvedValue(true);

        const attemptRes = await guard.attempt({ email: 'test@example.com', password: 'secret' }, true);
        expect(attemptRes).toBe(true);
        expect(guard.getLastAttempted()).toBe(fakeUser);

        const attemptWhenRes = await guard.attemptWhen({ email: 'test@example.com' });
        expect(attemptWhenRes).toBe(true);

        mockProvider.retrieveById.mockResolvedValue(fakeUser);
        const loginIdRes = await guard.loginUsingId(55);
        expect(loginIdRes).toBe(fakeUser);

        const onceIdRes = await guard.onceUsingId(55);
        expect(onceIdRes).toBe(fakeUser);

        const onceRes = await guard.once({ email: 'test@example.com' });
        expect(onceRes).toBe(true);
    });

    test('logoutCurrentDevice clears session and sets loggedOut', async () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        guard.setUser({ getAuthIdentifier: () => 1, getRememberToken: () => null });

        await guard.logoutCurrentDevice();
        expect(guard.hasUser()).toBe(false);
        expect(mockSession.remove).toHaveBeenCalledWith('login_web');
    });

    test('logout() cycles remember token when user has remember token', async () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        const fakeUser = {
            getAuthIdentifier: () => 1,
            getRememberToken: () => 'existing_token',
            setRememberToken: jest.fn()
        };
        guard.setUser(fakeUser);

        await guard.logout();
        expect(fakeUser.setRememberToken).toHaveBeenCalled();
        expect(mockProvider.updateRememberToken).toHaveBeenCalledWith(fakeUser, expect.any(String));
        expect(guard.hasUser()).toBe(false);
    });

    test('logoutOtherDevices returns early when user is null', async () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        mockSession.get.mockReturnValue(null);
        mockProvider.retrieveById.mockResolvedValue(null);

        expect(await guard.logoutOtherDevices('secret')).toBeUndefined();
    });

    test('loginUsingId() returns false when provider returns null', async () => {
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        mockProvider.retrieveById.mockResolvedValue(null);
        expect(await guard.loginUsingId(999)).toBe(false);
    });

    test('logoutOtherDevices rehashes password when authenticated', async () => {
        const fakeUser = {
            password: 'hashed_password',
            getAuthIdentifier: () => 1,
            getRememberToken: () => 'token',
            getAuthPassword: () => 'hashed_password',
            forceFill: function(data) {
                Object.assign(this, data);
                return this;
            },
            save: jest.fn().mockResolvedValue(true)
        };
        const guard = new SessionGuard('web', mockProvider, mockRequest);
        guard.user = jest.fn().mockResolvedValue(fakeUser);

        const mockHashInstance = {
            check: jest.fn().mockReturnValue(true),
            make: jest.fn().mockReturnValue('new_hashed_password')
        };

        const Hash = require('@ostro/support/facades/hash');
        Hash.setFacadeApplication({ instance: jest.fn() });
        Hash.swap(mockHashInstance);

        mockCookie.get.mockReturnValue('1|token|pass');
        const res = await guard.logoutOtherDevices('secret_password');
        expect(res).toBe(fakeUser);
        expect(mockCookie.forever).toHaveBeenCalled();

        mockHashInstance.check.mockReturnValue(false);
        await expect(guard.logoutOtherDevices('wrong_password')).rejects.toThrow();
    });
});
