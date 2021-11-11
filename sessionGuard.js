const GuardHelpers = require('./guardHelpers')
const uid = require('uid-safe').sync
const Recaller = require('./recaller')
const { implement } = require('@ostro/support/function')
const Session = require('@ostro/contracts/session/session')
const Hash = require('@ostro/support/facades/hash')
class SessionGuard extends GuardHelpers {

    $viaRemember = false;

    $lastAttempted = null;

    $loggedOut = false;

    $recallAttempted = false;

    $user = null;

    constructor($name, $provider, $request = null) {
        super()
        this.$request = $request
        this.$guardName = $name;
        this.$session = $request.session;
        this.$provider = $provider;
        this.$cookie = $request.cookie;
    }

    async user() {
        if (this.$loggedOut) {
            return;
        }

        if (!is_null(this.$user)) {
            return this.$user;
        }
        if (!this.$session) {
            return;
        }

        let $id = this.$session.get(this.getName());
        this.$user = await this.$provider.retrieveById($id)
        let $recaller = this.recaller()

        if (is_null(this.$user) && !is_null($recaller)) {
            this.$user = await this.userFromRecaller($recaller);
            if (this.$user) {
                this.updateSession(this.$user.getAuthIdentifier());

            }
        }

        return this.$user;
    }

    async userFromRecaller($recaller) {
        if (!$recaller.valid() || this.recallAttempted) {
            return;
        }

        this.recallAttempted = true;
        let $user = await this.$provider.retrieveByToken(
            $recaller.id(), $recaller.token()
        )
        this.$viaRemember = !is_null($user);

        return $user;
    }

    recaller() {
        if (is_null(this.$cookie)) {
            return;
        }
        let $recaller = this.$cookie.get(this.getRecallerName())
        if ($recaller) {
            return new Recaller($recaller);
        }
    }

    async id() {
        if (this.$loggedOut) {
            return;
        }

        return await await this.user() ?
            (await await this.user()).getAuthIdentifier() :
            this.$session.get(this.getName());
    }

    async once($credentials = {}) {
        if (await this.validate($credentials)) {
            this.setUser(this.$lastAttempted);

            return true;
        }

        return false;
    }

    async onceUsingId($id) {
        let $user = await this.$provider.retrieveById($id)

        if (!is_null($user)) {
            this.setUser($user);

            return $user;
        }

        return false;
    }

    async validate($credentials = {}) {
        let $user = await this.$provider.retrieveByCredentials($credentials)
        this.$lastAttempted = $user;

        return this.hasValidCredentials($user, $credentials);
    }

    async basic($field = 'email', $extraConditions = {}) {
        if (await this.check()) {
            return;
        }

        if (await this.attemptBasic(this.getRequest(), $field, $extraConditions)) {
            return;
        }

        return this.failedBasicResponse();
    }

    async onceBasic($field = 'email', $extraConditions = {}) {
        let $credentials = await this.basicCredentials(this.getRequest(), $field);

        if (!this.once(Object.assign($credentials, $extraConditions))) {
            return this.failedBasicResponse();
        }
    }

    attemptBasic($request, $field, $extraConditions = {}) {
        if (!$request.getUser()) {
            return false;
        }

        return this.attempt(Object.assign(
            this.basicCredentials($request, $field), $extraConditions
        ));
    }

    basicCredentials($request, $field) {
        return {
            $field: $request.getUser(),
            'password': $request.getPassword()
        };
    }

    failedBasicResponse() {
        throw new UnauthorizedHttpException('Basic', 'Invalid credentials.');
    }

    async attempt($credentials = {}, $remember = false) {

        let $user = await this.$provider.retrieveByCredentials($credentials);
        this.$lastAttempted = $user

        if (await this.hasValidCredentials($user, $credentials)) {
            await this.login($user, $remember);

            return true;
        }

        return false;
    }

    async attemptWhen($credentials = {}, $callbacks = null, $remember = false) {
        let $user = await this.$provider.retrieveByCredentials($credentials)
        this.$lastAttempted = $user;

        if (await this.hasValidCredentials($user, $credentials) && await this.shouldLogin($callbacks, $user)) {
            await this.login($user, $remember);

            return true;
        }

        return false;
    }

    async hasValidCredentials($user, $credentials) {
        let $validated = !is_null($user) && await this.$provider.validateCredentials($user, $credentials);

        return $validated;
    }

    shouldLogin($callbacks, $user) {

        return true;
    }

    async loginUsingId($id, $remember = false) {
        let $user = await this.$provider.retrieveById($id)
        if (!is_null($user)) {
            this.login($user, $remember);

            return $user;
        }

        return false;
    }

    async login($user, $remember = false) {
        this.updateSession($user.getAuthIdentifier());
        if ($remember) {
            await this.ensureRememberTokenIsSet($user);

            this.queueRecallerCookie($user);
        }

        this.setUser($user);
    }

    updateSession($id) {
        if (this.$session instanceof Session) {
            this.$session.put(this.getName(), $id);
        }

    }

    async ensureRememberTokenIsSet($user) {
        if (empty($user.getRememberToken())) {
            await this.cycleRememberToken($user);
        }
    }

    queueRecallerCookie($user) {
        this.createRecaller(
            $user.getAuthIdentifier() + '|' + $user.getRememberToken() + '|' + $user.getAuthPassword()
        );
    }

    createRecaller($value) {
        return this.getCookieJar().forever(this.getRecallerName(), $value);
    }

    async logout() {
        let $user = await this.user();

        this.clearUserDataFromStorage();

        if (!is_null(this.$user) && !empty($user.getRememberToken())) {
            await this.cycleRememberToken($user);
        }

        this.$user = null;

        this.$loggedOut = true;
        return true
    }

    async logoutCurrentDevice() {
        let $user = await this.user();

        this.clearUserDataFromStorage();

        this.$user = null;

        this.$loggedOut = true;
    }

    clearUserDataFromStorage() {
        this.$session.remove(this.getName());

    }

    cycleRememberToken($user) {
        let $token = uid(50)
        $user.setRememberToken($token);

        return this.$provider.updateRememberToken($user, $token);
    }

    async logoutOtherDevices($password, $attribute = 'password') {
        if (!await this.user()) {
            return;
        }

        let $result = await this.rehashUserPassword($password, $attribute);

        if (this.recaller()) {
            this.queueRecallerCookie(await this.user());
        }

        return $result;
    }

    async rehashUserPassword($password, $attribute) {
        if (!Hash.check($password, await this.user()[$attribute])) {
            throw new InvalidArgumentException('The given password does not match the current password.');
        }

        return tap(await this.user().forceFill({
            [$attribute]: Hash.make($password),
        })).save();
    }

    getLastAttempted() {
        return this.$lastAttempted;
    }

    getName() {
        return 'login_' + this.$guardName.toLowerCase()
    }

    getRecallerName() {
        return 'remember_' + this.$guardName.toLowerCase()
    }

    viaRemember() {
        return this.$viaRemember;
    }

    getCookieJar() {
        if (!isset(this.$cookie)) {
            throw new Error('Cookie jar has not been set.');
        }

        return this.$cookie;
    }

    setCookieJar($cookie) {
        this.$cookie = $cookie;
    }

    getSession() {
        return this.$session;
    }

    getUser() {
        return this.$user;
    }

    setUser($user) {
        this.$user = $user;

        this.$loggedOut = false;

        return this;
    }

    getRequest() {
        return this.$request;
    }

    setRequest($request) {
        this.$request = $request;

        return this;
    }
}

module.exports = SessionGuard