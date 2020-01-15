"use strict";
// Copyright 2018 The Casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const managementEnforcer_1 = require("./managementEnforcer");
const model_1 = require("./model");
const persist_1 = require("./persist");
const casbin_1 = require("./casbin");
/**
 * Enforcer = ManagementEnforcer + RBAC API.
 */
class Enforcer extends managementEnforcer_1.ManagementEnforcer {
    /**
     * initWithFile initializes an enforcer with a model file and a policy file.
     * @param modelPath model file path
     * @param policyPath policy file path
     */
    initWithFile(modelPath, policyPath) {
        return __awaiter(this, void 0, void 0, function* () {
            const a = new persist_1.FileAdapter(policyPath);
            yield this.initWithAdapter(modelPath, a);
        });
    }
    /**
     * initWithAdapter initializes an enforcer with a database adapter.
     * @param modelPath model file path
     * @param adapter current adapter instance
     */
    initWithAdapter(modelPath, adapter, filter = null) {
        return __awaiter(this, void 0, void 0, function* () {
            const m = casbin_1.newModel(modelPath, '');
            yield this.initWithModelAndAdapter(m, adapter, filter);
            this.modelPath = modelPath;
        });
    }
    /**
     * initWithModelAndAdapter initializes an enforcer with a model and a database adapter.
     * @param m model instance
     * @param adapter current adapter instance
     */
    initWithModelAndAdapter(m, adapter, filter = null) {
        return __awaiter(this, void 0, void 0, function* () {
            if (adapter) {
                this.adapter = adapter;
            }
            this.model = m;
            this.model.printModel();
            this.fm = model_1.FunctionMap.loadFunctionMap();
            this.initialize();
            if (this.adapter && filter) {
                // error intentionally ignored
                yield this.loadFilteredPolicy(filter);
            }
            if (this.adapter && !filter) {
                // error intentionally ignored
                yield this.loadPolicy();
            }
        });
    }
    /**
     * getRolesForUser gets the roles that a user has.
     *
     * @param name the user.
     * @param domain the domain.
     * @return the roles that the user has.
     */
    getRolesForUser(name, domain) {
        // @ts-ignore
        const rm = this.model.model.get('g').get('g').rm;
        if (domain == null) {
            return rm.getRoles(name);
        }
        else {
            return rm.getRoles(name, domain);
        }
    }
    /**
     * getUsersForRole gets the users that has a role.
     *
     * @param name the role.
     * @param domain the domain.
     * @return the users that has the role.
     */
    getUsersForRole(name, domain) {
        // @ts-ignore
        const rm = this.model.model.get('g').get('g').rm;
        if (domain == null) {
            return rm.getUsers(name);
        }
        else {
            return rm.getUsers(name, domain);
        }
    }
    /**
     * hasRoleForUser determines whether a user has a role.
     *
     * @param name the user.
     * @param role the role.
     * @param domain the domain.
     * @return whether the user has the role.
     */
    hasRoleForUser(name, role, domain) {
        const roles = this.getRolesForUser(name, domain);
        let hasRole = false;
        for (const r of roles) {
            if (r === role) {
                hasRole = true;
                break;
            }
        }
        return hasRole;
    }
    /**
     * addRoleForUser adds a role for a user.
     * Returns false if the user already has the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @param domain the domain.
     * @return succeeds or not.
     */
    addRoleForUser(user, role, domain) {
        return __awaiter(this, void 0, void 0, function* () {
            if (domain == null) {
                return yield this.addGroupingPolicy(user, role);
            }
            else {
                return yield this.addGroupingPolicy(user, role, domain);
            }
        });
    }
    /**
     * deleteRoleForUser deletes a role for a user.
     * Returns false if the user does not have the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @param domain the domain.
     * @return succeeds or not.
     */
    deleteRoleForUser(user, role, domain) {
        return __awaiter(this, void 0, void 0, function* () {
            if (domain == null) {
                return yield this.removeGroupingPolicy(user, role);
            }
            else {
                return yield this.removeGroupingPolicy(user, role, domain);
            }
        });
    }
    /**
     * deleteRolesForUser deletes all roles for a user.
     * Returns false if the user does not have any roles (aka not affected).
     *
     * @param user the user.
     * @param domain the domain.
     * @return succeeds or not.
     */
    deleteRolesForUser(user, domain) {
        return __awaiter(this, void 0, void 0, function* () {
            if (domain == null) {
                return yield this.removeFilteredGroupingPolicy(0, user);
            }
            else {
                return yield this.removeFilteredGroupingPolicy(0, user, '', domain);
            }
        });
    }
    /**
     * deleteUser deletes a user.
     * Returns false if the user does not exist (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    deleteUser(user) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.removeFilteredGroupingPolicy(0, user);
        });
    }
    /**
     * deleteRole deletes a role.
     *
     * @param role the role.
     * @return succeeds or not.
     */
    deleteRole(role) {
        return __awaiter(this, void 0, void 0, function* () {
            const res1 = yield this.removeFilteredGroupingPolicy(1, role);
            const res2 = yield this.removeFilteredPolicy(0, role);
            return res1 || res2;
        });
    }
    /**
     * deletePermission deletes a permission.
     * Returns false if the permission does not exist (aka not affected).
     *
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    deletePermission(...permission) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.removeFilteredPolicy(1, ...permission);
        });
    }
    /**
     * addPermissionForUser adds a permission for a user or role.
     * Returns false if the user or role already has the permission (aka not affected).
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    addPermissionForUser(user, ...permission) {
        return __awaiter(this, void 0, void 0, function* () {
            permission.unshift(user);
            return yield this.addPolicy(...permission);
        });
    }
    /**
     * deletePermissionForUser deletes a permission for a user or role.
     * Returns false if the user or role does not have the permission (aka not affected).
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    deletePermissionForUser(user, ...permission) {
        return __awaiter(this, void 0, void 0, function* () {
            permission.unshift(user);
            return yield this.removePolicy(...permission);
        });
    }
    /**
     * deletePermissionsForUser deletes permissions for a user or role.
     * Returns false if the user or role does not have any permissions (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    deletePermissionsForUser(user) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.removeFilteredPolicy(0, user);
        });
    }
    /**
     * getPermissionsForUser gets permissions for a user or role.
     *
     * @param user the user.
     * @return the permissions, a permission is usually like (obj, act). It is actually the rule without the subject.
     */
    getPermissionsForUser(user) {
        return this.getFilteredPolicy(0, user);
    }
    /**
     * hasPermissionForUser determines whether a user has a permission.
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return whether the user has the permission.
     */
    hasPermissionForUser(user, ...permission) {
        permission.unshift(user);
        return this.hasPolicy(...permission);
    }
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
    getImplicitRolesForUser(name, ...domain) {
        const res = [];
        const roles = this.rm.getRoles(name, ...domain);
        res.push(...roles);
        roles.forEach(n => {
            res.push(...this.getImplicitRolesForUser(n, ...domain));
        });
        return res;
    }
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
    getImplicitPermissionsForUser(user, ...domain) {
        return __awaiter(this, void 0, void 0, function* () {
            const roles = [user, ...(yield this.getImplicitRolesForUser(user, ...domain))];
            const res = [];
            const withDomain = domain && domain.length !== 0;
            roles.forEach(n => {
                if (withDomain) {
                    res.push(...this.getFilteredPolicy(0, n, ...domain));
                }
                else {
                    res.push(...this.getPermissionsForUser(n));
                }
            });
            return res;
        });
    }
}
exports.Enforcer = Enforcer;
