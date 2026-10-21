import InvalidArgumentException from '@ostro/support/exceptions/invalidArgumentException';
import { is_null, isset, call_user_func } from '@ostro/support/function';
import DatabaseUserProvider from './databaseUserProvider';
import EloquentUserProvider from './eloquentUserProvider';

/**
 * Class CreatesUserProviders.
 */
class CreatesUserProviders {
    public $customProviderCreators: Record<string, any> = {};

    declare public $container: any;

    /**
     * Create the given user provider instance.
     *
     * @param $provider - Provider name
     * @returns User provider instance or undefined
     */
    public createUserProvider($provider: any = null): any {
        const $config = this.getProviderConfiguration($provider);
        if (is_null($config)) {
            return;
        }
        const $driver = $config['driver'] || null;

        if (isset(this.$customProviderCreators[$driver])) {
            return call_user_func(
                this.$customProviderCreators[$driver],
                this.$container,
                $config
            );
        }

        switch ($driver) {
            case 'database':
                return this.createDatabaseProvider($config);
            case 'eloquent':
                return this.createEloquentProvider($config);
            default:
                throw new InvalidArgumentException(
                    `Authentication user provider [${$driver}] is not defined.`
                );
        }
    }

    /**
     * Get the user provider configuration.
     *
     * @param provider - Provider name
     * @returns Provider configuration object or undefined
     */
    public getProviderConfiguration(provider: any): any {
        provider = provider || this.getDefaultUserProvider();
        if (provider) {
            return this.$container.config.get(`auth.providers.${provider}`);
        }
    }

    /**
     * Create an instance of the database user provider.
     *
     * @param $config - Provider configuration
     * @returns Database user provider instance
     */
    public createDatabaseProvider($config: Record<string, any>): DatabaseUserProvider {
        const $connection = this.$container['db'].connection($config['connection'] || null);

        return new DatabaseUserProvider($connection, this.$container['hash'], $config['table']);
    }

    /**
     * Create an instance of the Eloquent user provider.
     *
     * @param $config - Provider configuration
     * @returns Eloquent user provider instance
     */
    public createEloquentProvider($config: Record<string, any>): EloquentUserProvider {
        return new EloquentUserProvider(this.$container['hash'], $config['model']);
    }

    /**
     * Get the default user provider name.
     *
     * @returns Default provider name
     */
    public getDefaultUserProvider(): string | undefined {
        return this.$container.config.get('auth.defaults.provider');
    }
}

export default CreatesUserProviders;