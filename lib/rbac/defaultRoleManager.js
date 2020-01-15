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
Object.defineProperty(exports, "__esModule", { value: true });
const log_1 = require("../log");
// RoleManager provides a default implementation for the RoleManager interface
class DefaultRoleManager {
    /**
     * DefaultRoleManager is the constructor for creating an instance of the
     * default RoleManager implementation.
     *
     * @param maxHierarchyLevel the maximized allowed RBAC hierarchy level.
     */
    constructor(maxHierarchyLevel) {
        this.allRoles = new Map();
        this.maxHierarchyLevel = maxHierarchyLevel;
    }
    /**
     * addLink adds the inheritance link between role: name1 and role: name2.
     * aka role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     */
    addLink(name1, name2, ...domain) {
        if (domain.length === 1) {
            name1 = domain[0] + '::' + name1;
            name2 = domain[0] + '::' + name2;
        }
        else if (domain.length > 1) {
            throw new Error('error: domain should be 1 parameter');
        }
        const role1 = this.createRole(name1);
        const role2 = this.createRole(name2);
        role1.addRole(role2);
    }
    /**
     * clear clears all stored data and resets the role manager to the initial state.
     */
    clear() {
        this.allRoles = new Map();
    }
    /**
     * deleteLink deletes the inheritance link between role: name1 and role: name2.
     * aka role: name1 does not inherit role: name2 any more.
     * domain is a prefix to the roles.
     */
    deleteLink(name1, name2, ...domain) {
        if (domain.length === 1) {
            name1 = domain[0] + '::' + name1;
            name2 = domain[0] + '::' + name2;
        }
        else if (domain.length > 1) {
            throw new Error('error: domain should be 1 parameter');
        }
        if (!this.hasRole(name1) || !this.hasRole(name2)) {
            return;
        }
        const role1 = this.createRole(name1);
        const role2 = this.createRole(name2);
        role1.deleteRole(role2);
    }
    /**
     * getRoles gets the roles that a subject inherits.
     * domain is a prefix to the roles.
     */
    getRoles(name, ...domain) {
        if (domain.length === 1) {
            name = domain[0] + '::' + name;
        }
        else if (domain.length > 1) {
            throw new Error('error: domain should be 1 parameter');
        }
        if (!this.hasRole(name)) {
            return [];
        }
        let roles = this.createRole(name).getRoles();
        if (domain.length === 1) {
            roles = roles.map(n => n.substring(domain[0].length + 2, n.length));
        }
        return roles;
    }
    /**
     * getUsers gets the users that inherits a subject.
     * domain is an unreferenced parameter here, may be used in other implementations.
     */
    getUsers(name, ...domain) {
        if (domain.length === 1) {
            name = domain[0] + '::' + name;
        }
        else if (domain.length > 1) {
            throw new Error('error: domain should be 1 parameter');
        }
        if (!this.hasRole(name)) {
            return [];
        }
        let users = [...this.allRoles.values()]
            .filter(n => n.hasDirectRole(name))
            .map(n => n.name);
        if (domain.length === 1) {
            users = users.map(n => n.substring(domain[0].length + 2, n.length));
        }
        return users;
    }
    /**
     * hasLink determines whether role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     */
    hasLink(name1, name2, ...domain) {
        if (domain.length === 1) {
            name1 = domain[0] + '::' + name1;
            name2 = domain[0] + '::' + name2;
        }
        else if (domain.length > 1) {
            throw new Error('error: domain should be 1 parameter');
        }
        if (name1 === name2) {
            return true;
        }
        if (!this.hasRole(name1) || !this.hasRole(name2)) {
            return false;
        }
        const role1 = this.createRole(name1);
        return role1.hasRole(name2, this.maxHierarchyLevel);
    }
    /**
     * printRoles prints all the roles to log.
     */
    printRoles() {
        [...this.allRoles.values()].map(n => {
            log_1.logPrint(n.toString());
        });
    }
    createRole(name) {
        const role = this.allRoles.get(name);
        if (role) {
            return role;
        }
        else {
            const newRole = new Role(name);
            this.allRoles.set(name, newRole);
            return newRole;
        }
    }
    hasRole(name) {
        return this.allRoles.has(name);
    }
}
exports.DefaultRoleManager = DefaultRoleManager;
/**
 * Role represents the data structure for a role in RBAC.
 */
class Role {
    constructor(name) {
        this.name = name;
        this.roles = [];
    }
    addRole(role) {
        if (this.roles.some(n => n.name === role.name)) {
            return;
        }
        this.roles.push(role);
    }
    deleteRole(role) {
        this.roles = this.roles.filter(n => n.name !== role.name);
    }
    hasRole(name, hierarchyLevel) {
        if (this.name === name) {
            return true;
        }
        if (hierarchyLevel <= 0) {
            return false;
        }
        for (const role of this.roles) {
            if (role.hasRole(name, hierarchyLevel - 1)) {
                return true;
            }
        }
        return false;
    }
    hasDirectRole(name) {
        return this.roles.some(n => n.name === name);
    }
    toString() {
        return this.name + this.roles.join(', ');
    }
    getRoles() {
        return this.roles.map(n => n.name);
    }
}
