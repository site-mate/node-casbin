import { ManagementEnforcer } from './managementEnforcer';
import { Model } from './model';
import { Adapter } from './persist';
/**
 * Enforcer = ManagementEnforcer + RBAC API.
 */
export declare class Enforcer extends ManagementEnforcer {
    /**
     * initWithFile initializes an enforcer with a model file and a policy file.
     * @param modelPath model file path
     * @param policyPath policy file path
     */
    initWithFile(modelPath: string, policyPath: string): Promise<void>;
    /**
     * initWithAdapter initializes an enforcer with a database adapter.
     * @param modelPath model file path
     * @param adapter current adapter instance
     */
    initWithAdapter(modelPath: string, adapter: Adapter, filter?: any): Promise<void>;
    /**
     * initWithModelAndAdapter initializes an enforcer with a model and a database adapter.
     * @param m model instance
     * @param adapter current adapter instance
     */
    initWithModelAndAdapter(m: Model, adapter: Adapter, filter?: any): Promise<void>;
    /**
     * getRolesForUser gets the roles that a user has.
     *
     * @param name the user.
     * @param domain the domain.
     * @return the roles that the user has.
     */
    getRolesForUser(name: string, domain?: string): string[];
    /**
     * getUsersForRole gets the users that has a role.
     *
     * @param name the role.
     * @param domain the domain.
     * @return the users that has the role.
     */
    getUsersForRole(name: string, domain?: string): string[];
    /**
     * hasRoleForUser determines whether a user has a role.
     *
     * @param name the user.
     * @param role the role.
     * @param domain the domain.
     * @return whether the user has the role.
     */
    hasRoleForUser(name: string, role: string, domain?: string): boolean;
    /**
     * addRoleForUser adds a role for a user.
     * Returns false if the user already has the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @param domain the domain.
     * @return succeeds or not.
     */
    addRoleForUser(user: string, role: string, domain?: string): Promise<boolean>;
    /**
     * deleteRoleForUser deletes a role for a user.
     * Returns false if the user does not have the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @param domain the domain.
     * @return succeeds or not.
     */
    deleteRoleForUser(user: string, role: string, domain?: string): Promise<boolean>;
    /**
     * deleteRolesForUser deletes all roles for a user.
     * Returns false if the user does not have any roles (aka not affected).
     *
     * @param user the user.
     * @param domain the domain.
     * @return succeeds or not.
     */
    deleteRolesForUser(user: string, domain?: string): Promise<boolean>;
    /**
     * deleteUser deletes a user.
     * Returns false if the user does not exist (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    deleteUser(user: string): Promise<boolean>;
    /**
     * deleteRole deletes a role.
     *
     * @param role the role.
     * @return succeeds or not.
     */
    deleteRole(role: string): Promise<boolean>;
    /**
     * deletePermission deletes a permission.
     * Returns false if the permission does not exist (aka not affected).
     *
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    deletePermission(...permission: string[]): Promise<boolean>;
    /**
     * addPermissionForUser adds a permission for a user or role.
     * Returns false if the user or role already has the permission (aka not affected).
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    addPermissionForUser(user: string, ...permission: string[]): Promise<boolean>;
    /**
     * deletePermissionForUser deletes a permission for a user or role.
     * Returns false if the user or role does not have the permission (aka not affected).
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    deletePermissionForUser(user: string, ...permission: string[]): Promise<boolean>;
    /**
     * deletePermissionsForUser deletes permissions for a user or role.
     * Returns false if the user or role does not have any permissions (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    deletePermissionsForUser(user: string): Promise<boolean>;
    /**
     * getPermissionsForUser gets permissions for a user or role.
     *
     * @param user the user.
     * @return the permissions, a permission is usually like (obj, act). It is actually the rule without the subject.
     */
    getPermissionsForUser(user: string): string[][];
    /**
     * hasPermissionForUser determines whether a user has a permission.
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return whether the user has the permission.
     */
    hasPermissionForUser(user: string, ...permission: string[]): boolean;
    /**
     * getImplicitRolesForUser gets implicit roles that a user has.
     * Compared to getRolesForUser(), this function retrieves indirect roles besides direct roles.
     * For example:
     * g, alice, role:admin
     * g, role:admin, role:user
     *
     * getRolesForUser("alice") can only get: ["role:admin"].
     * But getImplicitRolesForUser("alice") will get: ["role:admin", "role:user"].
     */
    getImplicitRolesForUser(name: string, ...domain: string[]): string[];
    /**
     * getImplicitPermissionsForUser gets implicit permissions for a user or role.
     * Compared to getPermissionsForUser(), this function retrieves permissions for inherited roles.
     * For example:
     * p, admin, data1, read
     * p, alice, data2, read
     * g, alice, admin
     *
     * getPermissionsForUser("alice") can only get: [["alice", "data2", "read"]].
     * But getImplicitPermissionsForUser("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
     */
    getImplicitPermissionsForUser(user: string, ...domain: string[]): Promise<string[][]>;
}
