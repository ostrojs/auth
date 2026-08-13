require('@ostro/support/helpers');
const Authenticatable = require('../authenticatable');
const AuthenticationException = require('../authenticationException');
const GenericUser = require('../genericUser');
const Recaller = require('../recaller');

describe('Authenticatable Trait/Class', () => {
    class User extends Authenticatable {
        getKeyName() {
            return 'id';
        }
    }

    test('getAuthIdentifierName returns key name', () => {
        const user = new User();
        expect(user.getAuthIdentifierName()).toBe('id');
    });

    test('getAuthIdentifier returns primary key value', () => {
        const user = new User();
        user.id = 42;
        expect(user.getAuthIdentifier()).toBe(42);
        expect(user.getAuthIdentifierForBroadcasting()).toBe(42);
    });

    test('getAuthPassword returns password property', () => {
        const user = new User();
        user.password = 'secret';
        expect(user.getAuthPassword()).toBe('secret');
    });

    test('remember token getter and setter', () => {
        const user = new User();
        expect(user.getRememberTokenName()).toBe('remember_token');
        user.setRememberToken('token123');
        expect(user.getRememberToken()).toBe('token123');
    });

    test('api token getter and setter', () => {
        const user = new User();
        expect(user.getApiTokenName()).toBe('api_token');
        user.setApiToken('api_token_xyz');
        expect(user.getApiToken()).toBe('api_token_xyz');
    });
});

describe('AuthenticationException', () => {
    test('creates exception with defaults', () => {
        const ex = new AuthenticationException();
        expect(ex.message).toBe('Unauthenticated.');
        expect(ex.guards()).toEqual([]);
        expect(ex.redirectTo()).toBeNull();
    });

    test('creates exception with custom params', () => {
        const ex = new AuthenticationException('Custom error', ['web', 'api'], '/login');
        expect(ex.message).toBe('Custom error');
        expect(ex.guards()).toEqual(['web', 'api']);
        expect(ex.redirectTo()).toBe('/login');
    });
});

describe('GenericUser', () => {
    test('attributes getter and setters', () => {
        const attributes = { id: 10, name: 'John Doe', password: 'hashed_pass' };
        const user = new GenericUser(attributes);

        expect(user.getAuthIdentifierName()).toBe('id');
        expect(user.getAuthIdentifier()).toBe(10);
        expect(user.getAuthPassword()).toBe('hashed_pass');
        expect(user.getRememberTokenName()).toBe('remember_token');
        expect(user.getApiTokenName()).toBe('api_token');

        user.setRememberToken('remember_abc');
        expect(user.getRememberToken()).toBe('remember_abc');

        user.setApiToken('api_xyz');
        expect(user.__get('api_token')).toBe('api_xyz');

        expect(user.toJSON()).toEqual(attributes);
    });

    test('magic getter and setter (__get / __set)', () => {
        const user = new GenericUser({ role: 'admin' });
        expect(user.__get('role')).toBe('admin');
        user.__set('role', 'superadmin');
        expect(user.__get('role')).toBe('superadmin');
    });
});

describe('Recaller Utility', () => {
    test('parses recaller string components', () => {
        const recaller = new Recaller('123|token_abc|hash_xyz');
        expect(recaller.id()).toBe('123');
        expect(recaller.token()).toBe('token_abc');
        expect(recaller.hash()).toBe('hash_xyz');
    });

    test('validates proper recaller format', () => {
        const validRecaller = new Recaller('123|token_abc|hash_xyz');
        expect(validRecaller.properString()).toBe(true);
        expect(validRecaller.hasAllSegments()).toBe(true);
        expect(validRecaller.valid()).toBe(true);
    });

    test('invalidates improper recaller format across multiple invalid scenarios', () => {
        // Missing segments (only 2 parts)
        const twoParts = new Recaller('123|token_abc');
        expect(twoParts.hasAllSegments()).toBe(false);
        expect(twoParts.valid()).toBe(false);

        // Empty first segment (id is whitespace/empty)
        const emptyId = new Recaller(' |token_abc|hash_xyz');
        expect(emptyId.hasAllSegments()).toBe(false);
        expect(emptyId.valid()).toBe(false);

        // Empty second segment (token is empty)
        const emptyToken = new Recaller('123||hash_xyz');
        expect(emptyToken.hasAllSegments()).toBe(false);
        expect(emptyToken.valid()).toBe(false);

        // No pipe character
        const noPipe = new Recaller('invalid_recaller_string');
        expect(noPipe.properString()).toBe(false);
        expect(noPipe.valid()).toBe(false);

        // Non-string input
        const numberInput = new Recaller(12345);
        expect(numberInput.properString()).toBe(false);
        expect(numberInput.valid()).toBe(false);
    });
});
