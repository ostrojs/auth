const InvalidArgumentException = require('@ostro/support/exceptions/invalidArgumentException')
const DatabaseUserProvider = require('./databaseUserProvider')
const EloquentUserProvider = require('./eloquentUserProvider')

class CreatesUserProviders {

    $customProviderCreators = {};

    createUserProvider($provider = null) {
        let $config = this.getProviderConfiguration($provider)
        if (is_null($config)) {
            return;
        }
        let $driver = ($config['driver'] || null)

        if (isset(this.$customProviderCreators[$driver])) {
            return call_user_func(
                this.$customProviderCreators[$driver], this.$app, $config
            );
        }

        switch ($driver) {
            case 'database':
                return this.createDatabaseProvider($config);
            case 'eloquent':
                return this.createEloquentProvider($config);
            default:
                throw new InvalidArgumentException(
                    `Authentication user provider [{$driver}] is not defined.`
                );
        }
    }

    getProviderConfiguration($provider) {
        $provider = $provider || this.getDefaultUserProvider()
        if ($provider) {
            return this.$app['config']['auth.providers.' + $provider];
        }
    }

    createDatabaseProvider($config) {
        let $connection = this.$app['db'].connection($config['connection'] || null);

        return new DatabaseUserProvider($connection, this.$app['hash'], $config['table']);
    }

    createEloquentProvider($config) {
        return new EloquentUserProvider(this.$app['hash'], $config['model']);
    }

    getDefaultUserProvider() {
        return this.$app['config']['auth.defaults.provider'];
    }
}

module.exports = CreatesUserProviders