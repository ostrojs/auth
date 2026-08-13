require('@ostro/support/helpers');
const TokenGuard = require('../tokenGuard');

describe('TokenGuard Unit Tests', () => {
    let mockProvider;
    let mockRequest;

    beforeEach(() => {
        mockProvider = {
            retrieveByCredentials: jest.fn(),
            validateCredentials: jest.fn()
        };
        mockRequest = {
            getQuery: jest.fn(),
            input: jest.fn(),
            bearerToken: jest.fn(),
            getPassword: jest.fn()
        };
    });

    test('getTokenForRequest extracts token from query parameter', () => {
        mockRequest.getQuery.mockReturnValue('token_from_query');
        const guard = new TokenGuard(mockProvider, mockRequest, 'api_token', 'api_token');
        expect(guard.getTokenForRequest()).toBe('token_from_query');
    });

    test('getTokenForRequest extracts token from body input if query is empty', () => {
        mockRequest.getQuery.mockReturnValue(null);
        mockRequest.input.mockReturnValue('token_from_input');
        const guard = new TokenGuard(mockProvider, mockRequest, 'api_token', 'api_token');
        expect(guard.getTokenForRequest()).toBe('token_from_input');
    });

    test('getTokenForRequest extracts bearer token if input is empty', () => {
        mockRequest.getQuery.mockReturnValue(null);
        mockRequest.input.mockReturnValue(null);
        mockRequest.bearerToken.mockReturnValue('token_from_bearer');
        const guard = new TokenGuard(mockProvider, mockRequest, 'api_token', 'api_token');
        expect(guard.getTokenForRequest()).toBe('token_from_bearer');
    });

    test('user() retrieves user using token from request', async () => {
        const fakeUser = { id: 1, name: 'Alice' };
        mockRequest.getQuery.mockReturnValue('valid_token');
        mockProvider.retrieveByCredentials.mockResolvedValue(fakeUser);

        const guard = new TokenGuard(mockProvider, mockRequest, 'api_token', 'api_token');
        const user = await guard.user();

        expect(mockProvider.retrieveByCredentials).toHaveBeenCalledWith({ api_token: 'valid_token' });
        expect(user).toEqual(fakeUser);
    });

    test('attempt() authenticates valid credentials', async () => {
        const fakeUser = { id: 10, name: 'Bob', getAuthIdentifier: () => 10 };
        mockProvider.retrieveByCredentials.mockResolvedValue(fakeUser);
        mockProvider.validateCredentials.mockResolvedValue(true);
        mockRequest.getQuery.mockReturnValue('valid_token');

        const guard = new TokenGuard(mockProvider, mockRequest, 'api_token', 'api_token');
        const result = await guard.attempt({ api_token: 'valid_token' });

        expect(result).toBe(true);
        expect(await guard.check()).toBe(true);
        expect(await guard.id()).toBe(10);
    });

    test('getTokenForRequest falls back to getPassword', () => {
        mockRequest.getQuery.mockReturnValue(null);
        mockRequest.input.mockReturnValue(null);
        mockRequest.bearerToken.mockReturnValue(null);
        mockRequest.getPassword.mockReturnValue('pass_token');

        const guard = new TokenGuard(mockProvider, mockRequest, 'api_token', 'api_token');
        expect(guard.getTokenForRequest()).toBe('pass_token');
    });

    test('user() retrieves user with hashed token option', async () => {
        mockRequest.getQuery.mockReturnValue('plain_token');
        const fakeUser = { id: 2 };
        mockProvider.retrieveByCredentials.mockResolvedValue(fakeUser);

        const guard = new TokenGuard(mockProvider, mockRequest, 'api_token', 'api_token', true);
        const user = await guard.user();

        expect(user).toBe(fakeUser);
        expect(mockProvider.retrieveByCredentials).toHaveBeenCalledWith({
            api_token: expect.any(String)
        });
    });

    test('attempt() returns false when credentials validation fails', async () => {
        mockProvider.retrieveByCredentials.mockResolvedValue(null);
        const guard = new TokenGuard(mockProvider, mockRequest);
        expect(await guard.attempt({})).toBe(false);
    });

    test('validate() returns true for matching credentials and false for non-matching or missing input', async () => {
        const guard = new TokenGuard(mockProvider, mockRequest);
        
        mockProvider.retrieveByCredentials.mockResolvedValueOnce({ id: 1 });
        expect(await guard.validate({ api_token: 'valid' })).toBe(true);

        mockProvider.retrieveByCredentials.mockResolvedValueOnce(null);
        expect(await guard.validate({ api_token: 'invalid' })).toBe(false);

        expect(await guard.validate({})).toBe(false);
    });
});
