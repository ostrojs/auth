require('@ostro/support/helpers');
const GuardHelpers = require('../guardHelpers');
const AuthenticationException = require('../authenticationException');

class TestGuard extends GuardHelpers {
    constructor(user = null, provider = null) {
        super();
        this.$user = user;
        this.$provider = provider;
    }
    async user() {
        return this.$user;
    }
}

describe('GuardHelpers Unit Tests', () => {
    test('authenticate() returns user when authenticated', async () => {
        const fakeUser = { id: 1 };
        const guard = new TestGuard(fakeUser);
        const result = await guard.authenticate();
        expect(result).toBe(fakeUser);
    });

    test('authenticate() throws AuthenticationException when null user', async () => {
        const guard = new TestGuard(null);
        await expect(guard.authenticate()).rejects.toThrow(AuthenticationException);
    });

    test('hasUser() returns boolean state', () => {
        const guard = new TestGuard({ id: 1 });
        expect(guard.hasUser()).toBe(true);

        guard.setUser(null);
        expect(guard.hasUser()).toBe(false);
    });

    test('check() and guest() return reciprocal booleans', async () => {
        const guardAuth = new TestGuard({ id: 1 });
        expect(await guardAuth.check()).toBe(true);
        expect(await guardAuth.guest()).toBe(false);

        const guardGuest = new TestGuard(null);
        expect(await guardGuest.check()).toBe(false);
        expect(await guardGuest.guest()).toBe(true);
    });

    test('id() returns auth identifier or undefined', async () => {
        const fakeUser = { getAuthIdentifier: () => 42 };
        const guardAuth = new TestGuard(fakeUser);
        expect(await guardAuth.id()).toBe(42);

        const guardGuest = new TestGuard(null);
        expect(await guardGuest.id()).toBeUndefined();
    });

    test('getProvider() and setProvider() getter and setter', () => {
        const guard = new TestGuard();
        const mockProvider = { name: 'mock' };
        guard.setProvider(mockProvider);
        expect(guard.getProvider()).toBe(mockProvider);
    });
});
