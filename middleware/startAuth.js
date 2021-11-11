class StartAuth {
    constructor() {
        this.$auth = this.$app['auth'];

        if (this.$auth instanceof require('../authManager')) {

            this.$registered = true;
            this.$startAuth = this.$auth.start();
        }
    }

    handle({request, response, next} ) {
    	if(!this.$registered){
            return next()
        }

        this.$startAuth(request, response, next)
    }
}

module.exports = StartAuth