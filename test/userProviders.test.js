require('@ostro/support/helpers');
const DatabaseUserProvider = require('../databaseUserProvider');
const EloquentUserProvider = require('../eloquentUserProvider');
const GenericUser = require('../genericUser');

describe('DatabaseUserProvider & EloquentUserProvider Unit Tests', () => {
    let mockConn;
    let mockHasher;
    let mockQuery;

    beforeEach(() => {
        mockQuery = {
            find: jest.fn(),
            where: jest.fn().mockReturnThis(),
            whereIn: jest.fn().mockReturnThis(),
            update: jest.fn(),
            first: jest.fn()
        };
        mockConn = {
            table: jest.fn().mockReturnValue(mockQuery)
        };
        mockHasher = {
            check: jest.fn()
        };
    });

    test('DatabaseUserProvider retrieveById returns GenericUser instance', async () => {
        const provider = new DatabaseUserProvider(mockConn, mockHasher, 'users');
        mockQuery.find.mockResolvedValue({ id: 10, email: 'test@example.com' });

        const user = await provider.retrieveById(10);
        expect(user).toBeInstanceOf(GenericUser);
        expect(user.getAuthIdentifier()).toBe(10);
        expect(mockConn.table).toHaveBeenCalledWith('users');
    });

    test('DatabaseUserProvider retrieveByToken returns GenericUser when token matches and null when mismatch/null', async () => {
        const provider = new DatabaseUserProvider(mockConn, mockHasher, 'users');
        mockQuery.first.mockResolvedValueOnce({ id: 1, remember_token: 'valid_token' });
        const userNull = await provider.retrieveByToken('id', 'wrong_token');
        expect(userNull).toBeNull();

        mockQuery.first.mockResolvedValueOnce(null);
        expect(await provider.retrieveByToken('id', 'token')).toBeNull();

        mockQuery.first.mockResolvedValueOnce({ id: 1, remember_token: 'valid_token' });
        const validUser = await provider.retrieveByToken('id', 'valid_token');
        expect(validUser).toBeInstanceOf(GenericUser);
    });

    test('DatabaseUserProvider validateCredentials checks hashed password', () => {
        const provider = new DatabaseUserProvider(mockConn, mockHasher, 'users');
        const fakeUser = new GenericUser({ password: 'hashed_password' });
        mockHasher.check.mockReturnValue(true);

        const result = provider.validateCredentials(fakeUser, { password: 'secretpassword' });
        expect(result).toBe(true);
        expect(mockHasher.check).toHaveBeenCalledWith('secretpassword', 'hashed_password');
    });

    test('DatabaseUserProvider retrieveByToken returns null when token or user fails match', async () => {
        const provider = new DatabaseUserProvider(mockConn, mockHasher, 'users');

        mockQuery.first.mockResolvedValueOnce(null);
        expect(await provider.retrieveByToken('id', 'secret_token')).toBeNull();

        mockQuery.first.mockResolvedValueOnce({ id: 1, remember_token: null });
        expect(await provider.retrieveByToken('id', 'secret_token')).toBeNull();

        mockQuery.first.mockResolvedValueOnce({ id: 1, remember_token: 'different_token' });
        expect(await provider.retrieveByToken('id', 'secret_token')).toBeNull();

        expect(provider.firstCredentialKey({})).toBeUndefined();

        // updateRememberToken
        const fakeUser = new GenericUser({ id: 1 });
        await provider.updateRememberToken(fakeUser, 'new_token');
        expect(mockQuery.update).toHaveBeenCalledWith({ remember_token: 'new_token' });

        // retrieveByCredentials empty check
        expect(await provider.retrieveByCredentials({})).toBeUndefined();
        expect(await provider.retrieveByCredentials({ password: '123' })).toBeUndefined();

        // retrieveByCredentials with array and scalar values
        mockQuery.first.mockResolvedValue({ id: 2, email: 'john@example.com' });
        const credUser = await provider.retrieveByCredentials({
            email: 'john@example.com',
            roles: ['admin', 'user'],
            password: 'secret_password'
        });
        expect(credUser).toBeInstanceOf(GenericUser);
        expect(mockQuery.whereIn).toHaveBeenCalledWith('roles', ['admin', 'user']);
    });

    test('EloquentUserProvider retrieveByToken, updateRememberToken, and retrieveByCredentials', async () => {
        class MockModel {
            getAuthIdentifierName() { return 'id'; }
            getRememberToken() { return 'eloquent_token'; }
            getAuthPassword() { return 'hashed_pass'; }
            setRememberToken(token) { this.remember_token = token; }
            save() { return Promise.resolve(true); }
            newQuery() { return mockQuery; }
        }

        const provider = new EloquentUserProvider(mockHasher, MockModel);

        // retrieveByToken null case & match case
        mockQuery.first.mockResolvedValueOnce(null);
        expect(await provider.retrieveByToken('id', 'eloquent_token')).toBeUndefined();

        const mockInstance = new MockModel();
        mockQuery.first.mockResolvedValue(mockInstance);
        const tokenUser = await provider.retrieveByToken('id', 'eloquent_token');
        expect(tokenUser).toBe(mockInstance);

        // updateRememberToken
        const updateRes = await provider.updateRememberToken(mockInstance, 'new_eloquent_token');
        expect(updateRes).toBe(true);

        // retrieveByCredentials
        expect(await provider.retrieveByCredentials({})).toBeUndefined();
        expect(await provider.retrieveByCredentials({ password: '123' })).toBeUndefined();

        const credUser = await provider.retrieveByCredentials({ email: 'jane@example.com', roles: ['editor'] });
        expect(credUser).toBe(mockInstance);

        // retrieveById
        mockQuery.first.mockResolvedValueOnce(mockInstance);
        expect(await provider.retrieveById(101)).toBe(mockInstance);

        // newModelQuery with null model argument
        expect(provider.newModelQuery()).toBe(mockQuery);

        // setHasher
        const mockHasher2 = { check: jest.fn().mockReturnValue(true) };
        provider.setHasher(mockHasher2);
        expect(provider.getHasher()).toBe(mockHasher2);

        // validateCredentials
        expect(provider.validateCredentials(mockInstance, { password: 'secret' })).toBe(true);

        // setModel
        class AnotherModel {
            getAuthIdentifierName() {
                return 'id';
            }
            newQuery() {
                return mockQuery;
            }
        }
        provider.setModel(AnotherModel);
        expect(provider.getModel()).toBe(AnotherModel);

        // retrieveByCredentials password filtering & array credentials
        mockQuery.first.mockResolvedValueOnce(mockInstance);
        const credRes = await provider.retrieveByCredentials({ username: 'john', roles: ['admin', 'user'], password: 'secretpassword' });
        expect(credRes).toBe(mockInstance);

        // retrieveByToken mismatch branch
        mockInstance.getRememberToken = jest.fn().mockReturnValue('correct_token');
        mockQuery.first.mockResolvedValueOnce(mockInstance);
        expect(await provider.retrieveByToken(1, 'wrong_token')).toBeNull();

        // firstCredentialKey fallback
        expect(provider.firstCredentialKey({})).toBeUndefined();
    });

    test('EloquentUserProvider getter and setter for hasher and model', () => {
        class MockModel {}
        const provider = new EloquentUserProvider(mockHasher, MockModel);

        expect(provider.getModel()).toBe(MockModel);
        expect(provider.getHasher()).toBe(mockHasher);
    });
});
