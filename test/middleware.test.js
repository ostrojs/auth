require('@ostro/support/helpers');
const Authenticate = require('../middleware/authenticate');
const RedirectIfAuthenticated = require('../middleware/redirectIfAuthenticated');
const StartAuth = require('../middleware/startAuth');
const AuthenticationException = require('../authenticationException');
const AuthManager = require('../authManager');

describe('Middleware Multi-Scenario Unit Tests', () => {

    describe('Authenticate Middleware', () => {
        test('passes when guard check succeeds', async () => {
            const middleware = new Authenticate('web');
            const mockUser = { id: 1 };
            const mockRequest = {
                auth: {
                    guard: jest.fn().mockReturnValue({
                        check: jest.fn().mockResolvedValue(true)
                    }),
                    shouldUse: jest.fn().mockResolvedValue(mockUser)
                }
            };
            const mockNext = jest.fn().mockResolvedValue('next_passed');

            const result = await middleware.handle({ request: mockRequest, next: mockNext });

            expect(result).toBe('next_passed');
            expect(mockNext).toHaveBeenCalled();
            expect(mockRequest.auth.guard).toHaveBeenCalledWith('web');
            expect(mockRequest.auth.shouldUse).toHaveBeenCalledWith('web');
        });

        test('throws AuthenticationException when no guards pass', async () => {
            const middleware = new Authenticate('web', 'api');
            const mockRequest = {
                auth: {
                    guard: jest.fn().mockReturnValue({
                        check: jest.fn().mockResolvedValue(false)
                    })
                }
            };
            const mockNext = jest.fn();

            await expect(middleware.handle({ request: mockRequest, next: mockNext }))
                .rejects.toThrow(AuthenticationException);
            expect(mockNext).not.toHaveBeenCalled();
        });

        test('loops through multiple guards until one passes', async () => {
            const middleware = new Authenticate('web', 'api');
            const mockUser = { id: 2 };
            const mockRequest = {
                auth: {
                    guard: jest.fn().mockImplementation((g) => ({
                        check: jest.fn().mockResolvedValue(g === 'api')
                    })),
                    shouldUse: jest.fn().mockResolvedValue(mockUser)
                }
            };
            const mockNext = jest.fn().mockResolvedValue('passed_api');

            const result = await middleware.handle({ request: mockRequest, next: mockNext });
            expect(result).toBe('passed_api');
            expect(mockRequest.auth.shouldUse).toHaveBeenCalledWith('api');
        });

        test('handles empty guards default to [null]', async () => {
            const middleware = new Authenticate();
            const mockRequest = {
                auth: {
                    guard: jest.fn().mockReturnValue({
                        check: jest.fn().mockResolvedValue(true)
                    }),
                    shouldUse: jest.fn().mockResolvedValue({ id: 9 })
                }
            };
            const mockNext = jest.fn().mockResolvedValue('ok');

            await middleware.handle({ request: mockRequest, next: mockNext });

            expect(mockRequest.auth.guard).toHaveBeenCalledWith(null);
        });
    });

    describe('RedirectIfAuthenticated Middleware', () => {
        test('redirects when user is authenticated', async () => {
            const middleware = new RedirectIfAuthenticated('web');
            const mockAuth = {
                guard: jest.fn().mockReturnValue({
                    check: jest.fn().mockResolvedValue(true)
                })
            };
            const mockRedirect = {
                to: jest.fn().mockReturnValue('redirected_to_home')
            };
            const mockNext = jest.fn();

            const result = await middleware.handle({
                request: {},
                next: mockNext,
                auth: mockAuth,
                redirect: mockRedirect
            });

            expect(result).toBe('redirected_to_home');
            expect(mockRedirect.to).toHaveBeenCalledWith('/');
            expect(mockNext).not.toHaveBeenCalled();
        });

        test('proceeds to next when guest user and handles empty guards constructor', async () => {
            const middleware = new RedirectIfAuthenticated();
            const mockAuth = {
                guard: jest.fn().mockReturnValue({
                    check: jest.fn().mockResolvedValue(false)
                })
            };
            const mockRedirect = { to: jest.fn() };
            const mockNext = jest.fn().mockResolvedValue('next_passed');

            const result = await middleware.handle({
                request: {},
                next: mockNext,
                auth: mockAuth,
                redirect: mockRedirect
            });

            expect(result).toBe('next_passed');
            expect(mockAuth.guard).toHaveBeenCalledWith(null);
            expect(mockNext).toHaveBeenCalled();
        });
    });

    describe('StartAuth Middleware', () => {
        test('registers start handler if auth app instance matches AuthManager', () => {
            const mockManager = Object.create(AuthManager.prototype);
            const mockStartFn = jest.fn();
            mockManager.start = jest.fn().mockReturnValue(mockStartFn);

            const mockAppInstance = { auth: mockManager };
            const middleware = Object.create(StartAuth.prototype);
            middleware.$app = mockAppInstance;
            middleware.$auth = mockAppInstance['auth'];
            if (middleware.$auth instanceof AuthManager) {
                middleware.$registered = true;
                middleware.$startAuth = middleware.$auth.start();
            }

            const req = {};
            const res = {};
            const next = jest.fn();

            middleware.handle({ request: req, response: res, next });
            expect(mockStartFn).toHaveBeenCalledWith(req, res, next);
        });

        test('StartAuth constructor executes when global app or this.$app is bound', () => {
            const mockManager = Object.create(AuthManager.prototype);
            mockManager.start = jest.fn().mockReturnValue(jest.fn());

            Object.defineProperty(StartAuth.prototype, '$app', {
                get: () => ({ auth: mockManager }),
                configurable: true
            });

            const instance = new StartAuth();
            expect(instance.$registered).toBe(true);
            delete StartAuth.prototype.$app;
        });

        test('passes next directly when not registered', () => {
            const middleware = Object.create(StartAuth.prototype);
            middleware.$registered = false;

            const next = jest.fn().mockReturnValue('unregistered_next');
            const result = middleware.handle({ request: {}, response: {}, next });

            expect(result).toBe('unregistered_next');
            expect(next).toHaveBeenCalled();
        });
    });
});
