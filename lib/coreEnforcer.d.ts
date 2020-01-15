import { Effector } from './effect';
import { FunctionMap, Model } from './model';
import { Adapter, Filter, FilteredAdapter, Watcher } from './persist';
import { RoleManager } from './rbac';
/**
 * CoreEnforcer defines the core functionality of an enforcer.
 */
export declare class CoreEnforcer {
    protected modelPath: string;
    protected model: Model;
    protected fm: FunctionMap;
    private eft;
    protected adapter: FilteredAdapter | Adapter;
    protected watcher: Watcher | null;
    protected rm: RoleManager;
    private enabled;
    protected autoSave: boolean;
    protected autoBuildRoleLinks: boolean;
    initialize(): void;
    /**
     * loadModel reloads the model from the model CONF file.
     * Because the policy is attached to a model,
     * so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
     */
    loadModel(): void;
    /**
     * getModel gets the current model.
     *
     * @return the model of the enforcer.
     */
    getModel(): Model;
    /**
     * setModel sets the current model.
     *
     * @param m the model.
     */
    setModel(m: Model): void;
    /**
     * getAdapter gets the current adapter.
     *
     * @return the adapter of the enforcer.
     */
    getAdapter(): Adapter;
    /**
     * setAdapter sets the current adapter.
     *
     * @param adapter the adapter.
     */
    setAdapter(adapter: Adapter): void;
    /**
     * setWatcher sets the current watcher.
     *
     * @param watcher the watcher.
     */
    setWatcher(watcher: Watcher): void;
    /**
     * setRoleManager sets the current role manager.
     *
     * @param rm the role manager.
     */
    setRoleManager(rm: RoleManager): void;
    /**
     * setEffector sets the current effector.
     *
     * @param eft the effector.
     */
    setEffector(eft: Effector): void;
    /**
     * clearPolicy clears all policy.
     */
    clearPolicy(): void;
    /**
     * loadPolicy reloads the policy from file/database.
     */
    loadPolicy(): Promise<void>;
    /**
     * loadFilteredPolicy reloads a filtered policy from file/database.
     *
     * @param filter the filter used to specify which type of policy should be loaded.
     */
    loadFilteredPolicy(filter: Filter): Promise<boolean>;
    /**
     * isFiltered returns true if the loaded policy has been filtered.
     *
     * @return if the loaded policy has been filtered.
     */
    isFiltered(): boolean;
    /**
     * savePolicy saves the current policy (usually after changed with
     * Casbin API) back to file/database.
     */
    savePolicy(): Promise<boolean>;
    /**
     * enableEnforce changes the enforcing state of Casbin, when Casbin is
     * disabled, all access will be allowed by the enforce() function.
     *
     * @param enable whether to enable the enforcer.
     */
    enableEnforce(enable: boolean): void;
    /**
     * enableLog changes whether to print Casbin log to the standard output.
     *
     * @param enable whether to enable Casbin's log.
     */
    enableLog(enable: boolean): void;
    /**
     * enableAutoSave controls whether to save a policy rule automatically to
     * the adapter when it is added or removed.
     *
     * @param autoSave whether to enable the AutoSave feature.
     */
    enableAutoSave(autoSave: boolean): void;
    /**
     * enableAutoBuildRoleLinks controls whether to save a policy rule
     * automatically to the adapter when it is added or removed.
     *
     * @param autoBuildRoleLinks whether to automatically build the role links.
     */
    enableAutoBuildRoleLinks(autoBuildRoleLinks: boolean): void;
    /**
     * buildRoleLinks manually rebuild the
     * role inheritance relations.
     */
    buildRoleLinks(): void;
    /**
     * enforce decides whether a "subject" can access a "object" with
     * the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param rvals the request needs to be mediated, usually an array
     *              of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    enforce(...rvals: any[]): boolean;
}
