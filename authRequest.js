const { Macroable } = require('@ostro/support/macro')

class Auth extends Macroable {

    $request;

    $manager;

    $guards = {};

    constructor(request, manager) {
        super()
        this.$request = request;
        this.$manager = manager;
        this.$defaultGuard = this.$manager.getDefaultDriver();
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