const { Macroable } = require('@ostro/support/macro')

class Auth extends Macroable {

    constructor(request, manager) {
        super()
        Object.defineProperties(this, {
            $request: {
                value: request
            },
            $manager: {
                value: manager,
            },
            $defaultGuard: {
                value: manager.getDefaultDriver(),
                writable: true
            },
            $guards: {
                value: {},
                writable: true
            }
        })
    }

    guard($name) {
        if (!$name) {
            $name = this.$defaultGuard
        }
        return this.$guards[$name] = this.$guards[$name] || this.$manager.guard($name)(this.$request)
    }

    shouldUse($name) {
        $name = $name || this.$defaultGuard;

        this.setDefaultDriverForCurrentRequest($name);

        return this.guard($name).user();
    }

    setDefaultDriverForCurrentRequest($name) {
        this.$defaultGuard = $name;
    }

    __get(target, method) {
        return this.make(target.guard(this.$defaultGuard), method)
    }

}
module.exports = Auth