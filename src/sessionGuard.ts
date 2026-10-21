import GuardHelpers from './guardHelpers';
import * as uidSafeModule from 'uid-safe';
const uidSafe: any = (uidSafeModule as any).default || uidSafeModule;
import Recaller from './recaller';
import Session from '@ostro/contracts/session/session';
import Hash from '@ostro/support/facades/hash';
import InvalidArgumentException from '@ostro/support/exceptions/invalidArgumentException';
import { is_null, empty, isset, tap } from '@ostro/support/function';

const uid = uidSafe.sync;

// Framework globals registered by OstroJS at boot time
declare const UnauthorizedHttpException: any;

/**
 * Class SessionGuard.
 */
class SessionGuard extends GuardHelpers {
    public $viaRemember: boolean = false;
    public $lastAttempted: any = null;
    public $loggedOut: boolean = false;
    public $recallAttempted: boolean = false;
    public recallAttempted: boolean = false;
    public $user: any = null;
    public $request: any;
    public $guardName: string;
    public $session: any;
    declare public $provider: any;
    public $cookie: any;

    /**
     * Create a new session guard instance.
     *
     * @param $name - Guard name
     * @param $provider - User provider instance
     * @param $request - Request instance
     */
    constructor($name: string, $provider: any, $request: any = null) {
        super();
        this.$request = $request;
        this.$guardName = $name;
        this.$session = $request?.session;
        this.$provider = $provider;
        this.$cookie = $request?.cookie;
    }

    /**
     * Get the currently authenticated user.
     *
     * @returns Authenticated user model or undefined
     */
    public async user(): Promise<any> {
        if (this.$loggedOut) {
            return;
        }

        if (!is_null(this.$user)) {
            return this.$user;
        }
        if (!this.$session) {
            return;
        }

        const $id = this.$session.get(this.getName());
        this.$user = await this.$provider.retrieveById($id);
        const $recaller = this.recaller();

        if (is_null(this.$user) && !is_null($recaller) && $recaller !== undefined) {
            this.$user = await this.userFromRecaller($recaller);
            if (this.$user) {
                this.updateSession(this.$user.getAuthIdentifier());
            }
        }

        return this.$user;
    }

    /**
     * Pull a user from the repository by token from recaller.
     *
     * @param $recaller - Recaller instance
     * @returns User instance or undefined
     */
    public async userFromRecaller($recaller: any): Promise<any> {
        if (!$recaller.valid() || this.recallAttempted) {
            return;
        }

        this.recallAttempted = true;
        const $user = await this.$provider.retrieveByToken(
            $recaller.id(),
            $recaller.token()
        );
        this.$viaRemember = !is_null($user);

        return $user;
    }

    /**
     * Get the decrypted recaller cookie for the request.
     *
     * @returns Recaller instance or undefined
     */
    public recaller(): Recaller | undefined {
        if (is_null(this.$cookie)) {
            return;
        }
        const $recaller = this.$cookie.get(this.getRecallerName());
        if ($recaller) {
            return new Recaller($recaller);
        }
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @returns User ID or session identifier
     */
    public async id(): Promise<any> {
        if (this.$loggedOut) {
            return;
        }

        const user = await this.user();
        return user ? user.getAuthIdentifier() : this.$session?.get(this.getName());
    }

    /**
     * Log a user into the application without sessions or cookies.
     *
     * @param $credentials - User credentials
     * @returns True if authentication succeeded
     */
    public async once($credentials: Record<string, any> = {}): Promise<boolean> {
        if (await this.validate($credentials)) {
            this.setUser(this.$lastAttempted);

            return true;
        }

        return false;
    }

    /**
     * Log the given user ID into the application without sessions or cookies.
     *
     * @param $id - User ID
     * @returns Authenticated user or false
     */
    public async onceUsingId($id: string): Promise<any> {
        const $user = await this.$provider.retrieveById($id);

        if (!is_null($user)) {
            this.setUser($user);

            return $user;
        }

        return false;
    }

    /**
     * Validate a user's credentials.
     *
     * @param $credentials - User credentials
     * @returns True if credentials are valid
     */
    public async validate($credentials: Record<string, any> = {}): Promise<boolean> {
        const $user = await this.$provider.retrieveByCredentials($credentials);
        this.$lastAttempted = $user;

        return this.hasValidCredentials($user, $credentials);
    }

    /**
     * Attempt to authenticate using HTTP Basic Auth.
     *
     * @param $field - Username field
     * @param $extraConditions - Additional conditions
     */
    public async basic($field: string = 'email', $extraConditions: Record<string, any> = {}): Promise<any> {
        if (await this.check()) {
            return;
        }

        if (await this.attemptBasic(this.getRequest(), $field, $extraConditions)) {
            return;
        }

        return this.failedBasicResponse();
    }

    /**
     * Perform a stateless HTTP Basic authentication attempt.
     *
     * @param $field - Username field
     * @param $extraConditions - Additional conditions
     */
    public async onceBasic($field: string = 'email', $extraConditions: Record<string, any> = {}): Promise<any> {
        const $credentials = await this.basicCredentials(this.getRequest(), $field);

        if (!(await this.once(Object.assign($credentials, $extraConditions)))) {
            return this.failedBasicResponse();
        }
    }

    /**
     * Attempt to authenticate using basic credentials.
     *
     * @param $request - Request instance
     * @param $field - Field name
     * @param $extraConditions - Additional conditions
     * @returns True if attempt passed
     */
    public attemptBasic($request: any, $field: string, $extraConditions: Record<string, any> = {}): Promise<boolean> | boolean {
        if (!$request.getUser()) {
            return false;
        }

        return this.attempt(
            Object.assign(this.basicCredentials($request, $field), $extraConditions)
        );
    }

    /**
     * Get the credential array for HTTP Basic Auth.
     *
     * @param $request - Request instance
     * @param $field - Field name
     * @returns Credentials dictionary
     */
    public basicCredentials($request: any, $field: string): Record<string, any> {
        return {
            [$field]: $request.getUser(),
            'password': $request.getPassword(),
        };
    }

    /**
     * Throw failed basic auth response.
     */
    public failedBasicResponse(): never {
        throw new UnauthorizedHttpException('Basic', 'Invalid credentials.');
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param $credentials - User credentials
     * @param $remember - Whether to set remember cookie
     * @returns True if authentication succeeded
     */
    public async attempt($credentials: Record<string, any> = {}, $remember: boolean = false): Promise<boolean> {
        const $user = await this.$provider.retrieveByCredentials($credentials);
        this.$lastAttempted = $user;

        if (await this.hasValidCredentials($user, $credentials)) {
            await this.login($user, $remember);

            return true;
        }

        return false;
    }

    /**
     * Attempt to authenticate a user with optional callback filter.
     *
     * @param $credentials - User credentials
     * @param $callbacks - Validation callback
     * @param $remember - Whether to remember
     * @returns True if authentication succeeded
     */
    public async attemptWhen($credentials: Record<string, any> = {}, $callbacks: any = null, $remember: boolean = false): Promise<boolean> {
        const $user = await this.$provider.retrieveByCredentials($credentials);
        this.$lastAttempted = $user;

        if ((await this.hasValidCredentials($user, $credentials)) && (await this.shouldLogin($callbacks, $user))) {
            await this.login($user, $remember);

            return true;
        }

        return false;
    }

    /**
     * Determine if the user matches credentials.
     *
     * @param $user - User model
     * @param $credentials - User credentials
     * @returns True if valid
     */
    public async hasValidCredentials($user: any, $credentials: Record<string, any>): Promise<boolean> {
        const $validated = !is_null($user) && (await this.$provider.validateCredentials($user, $credentials));

        return $validated;
    }

    /**
     * Determine if the user should be logged in.
     *
     * @param $callbacks - Callback or array of callbacks
     * @param $user - User model
     * @returns True if login should proceed
     */
    public shouldLogin($callbacks: any, $user: Record<string, any>): boolean {
        return true;
    }

    /**
     * Log the given user ID into the application.
     *
     * @param $id - User ID
     * @param $remember - Whether to remember
     * @returns Logged in user or false
     */
    public async loginUsingId($id: string, $remember: boolean = false): Promise<any> {
        const $user = await this.$provider.retrieveById($id);
        if (!is_null($user)) {
            await this.login($user, $remember);

            return $user;
        }

        return false;
    }

    /**
     * Log a user into the application.
     *
     * @param $user - User model
     * @param $remember - Whether to remember
     */
    public async login($user: Record<string, any>, $remember: boolean = false): Promise<void> {
        this.updateSession($user.getAuthIdentifier());
        if ($remember) {
            await this.ensureRememberTokenIsSet($user);

            this.queueRecallerCookie($user);
        }

        this.setUser($user);
    }

    /**
     * Update the session with the given ID.
     *
     * @param $id - User ID
     */
    public updateSession($id: string): void {
        if (this.$session instanceof Session) {
            this.$session.put(this.getName(), $id);
        }
    }

    /**
     * Ensure the remember token is set on the user.
     *
     * @param $user - User instance
     */
    public async ensureRememberTokenIsSet($user: Record<string, any>): Promise<void> {
        if (empty($user.getRememberToken())) {
            await this.cycleRememberToken($user);
        }
    }

    /**
     * Queue the recaller cookie into the cookie jar.
     *
     * @param $user - User instance
     */
    public queueRecallerCookie($user: Record<string, any>): void {
        this.createRecaller(
            $user.getAuthIdentifier() + '|' + $user.getRememberToken() + '|' + $user.getAuthPassword()
        );
    }

    /**
     * Create a "remember me" cookie for the user.
     *
     * @param $value - Recaller value
     * @returns Created cookie
     */
    public createRecaller($value: any): any {
        return this.getCookieJar().forever(this.getRecallerName(), $value);
    }

    /**
     * Log the user out of the application.
     *
     * @returns True if logged out
     */
    public async logout(): Promise<boolean> {
        const $user = await this.user();

        this.clearUserDataFromStorage();

        if (!is_null(this.$user) && !empty($user.getRememberToken())) {
            await this.cycleRememberToken($user);
        }

        this.$user = null;
        this.$loggedOut = true;

        return true;
    }

    /**
     * Log the current user out of the current device.
     */
    public async logoutCurrentDevice(): Promise<void> {
        await this.user();

        this.clearUserDataFromStorage();

        this.$user = null;
        this.$loggedOut = true;
    }

    /**
     * Remove the user data from the session and cookies.
     */
    public clearUserDataFromStorage(): void {
        this.$session?.remove(this.getName());
    }

    /**
     * Refresh the remember token on user model and database.
     *
     * @param $user - User model
     * @returns Update promise
     */
    public cycleRememberToken($user: Record<string, any>): any {
        const $token = uid(50);
        $user.setRememberToken($token);

        return this.$provider.updateRememberToken($user, $token);
    }

    /**
     * Log the user out of all devices except the current one.
     *
     * @param $password - Plain text password
     * @param $attribute - Password attribute name
     * @returns Saved user or undefined
     */
    public async logoutOtherDevices($password: string, $attribute: string = 'password'): Promise<any> {
        if (!(await this.user())) {
            return;
        }

        const $result = await this.rehashUserPassword($password, $attribute);

        if (this.recaller()) {
            this.queueRecallerCookie(await this.user());
        }

        return $result;
    }

    /**
     * Rehash the user's password.
     *
     * @param $password - Plain text password
     * @param $attribute - Password attribute name
     * @returns User save result
     */
    public async rehashUserPassword($password: string, $attribute: string): Promise<any> {
        const $user = await this.user();
        if (!Hash.check($password, $user[$attribute])) {
            throw new InvalidArgumentException('The given password does not match the current password.');
        }

        return tap(
            await $user.forceFill({
                [$attribute]: Hash.make($password),
            }),
            ($u: any) => $u.save()
        );
    }

    /**
     * Get the last user attempted to be authenticated.
     *
     * @returns Last attempted user
     */
    public getLastAttempted(): any {
        return this.$lastAttempted;
    }

    /**
     * Get a unique identifier for the auth session value.
     *
     * @returns Session key name
     */
    public getName(): string {
        return 'login_' + this.$guardName.toLowerCase();
    }

    /**
     * Get the name of the cookie used to store the "recaller".
     *
     * @returns Recaller cookie name
     */
    public getRecallerName(): string {
        return 'remember_' + this.$guardName.toLowerCase();
    }

    /**
     * Determine if the user was authenticated via "remember me" cookie.
     *
     * @returns True if via remember
     */
    public viaRemember(): boolean {
        return this.$viaRemember;
    }

    /**
     * Get the cookie creator instance used by the guard.
     *
     * @returns Cookie jar instance
     */
    public getCookieJar(): any {
        if (!isset(this.$cookie)) {
            throw new Error('Cookie jar has not been set.');
        }

        return this.$cookie;
    }

    /**
     * Set the cookie creator instance used by the guard.
     *
     * @param $cookie - Cookie jar instance
     */
    public setCookieJar($cookie: any): void {
        this.$cookie = $cookie;
    }

    /**
     * Get the session store used by the guard.
     *
     * @returns Session instance
     */
    public getSession(): any {
        return this.$session;
    }

    /**
     * Get the user instance.
     *
     * @returns User instance
     */
    public getUser(): any {
        return this.$user;
    }

    /**
     * Set the current user.
     *
     * @param $user - User model
     * @returns Current guard instance
     */
    public setUser($user: any): this {
        this.$user = $user;
        this.$loggedOut = false;

        return this;
    }

    /**
     * Get the current request instance.
     *
     * @returns Request instance
     */
    public getRequest(): any {
        return this.$request;
    }

    /**
     * Set the current request instance.
     *
     * @param $request - Request instance
     * @returns Current guard instance
     */
    public setRequest($request: any): this {
        this.$request = $request;

        return this;
    }
}

export default SessionGuard;