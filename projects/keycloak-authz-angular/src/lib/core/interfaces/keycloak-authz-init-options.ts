export interface KeycloakAuthzInitOptions {
    /**
     * if set to true, load all permissions for default resource-server
     * at initialization of adapter
     *
     */
    loadPermissionsInStartup?: boolean;

    /**
     * specifies the default resource-server where the entitlements are loaded from
     * after adapter initialization
     *
     * Is only relevant if loadPermissionsInStartup is set to true
     *
     */
    defaultResourceServerId?: string;

}
