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
const internalEnforcer_1 = require("./internalEnforcer");
/**
 * ManagementEnforcer = InternalEnforcer + Management API.
 */
class ManagementEnforcer extends internalEnforcer_1.InternalEnforcer {
    /**
     * getAllSubjects gets the list of subjects that show up in the current policy.
     *
     * @return all the subjects in "p" policy rules. It actually collects the
     *         0-index elements of "p" policy rules. So make sure your subject
     *         is the 0-index element, like (sub, obj, act). Duplicates are removed.
     */
    getAllSubjects() {
        return this.getAllNamedSubjects('p');
    }
    /**
     * getAllNamedSubjects gets the list of subjects that show up in the currentnamed policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return all the subjects in policy rules of the ptype type. It actually
     *         collects the 0-index elements of the policy rules. So make sure
     *         your subject is the 0-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    getAllNamedSubjects(ptype) {
        return this.model.getValuesForFieldInPolicy('p', ptype, 0);
    }
    /**
     * getAllObjects gets the list of objects that show up in the current policy.
     *
     * @return all the objects in "p" policy rules. It actually collects the
     *         1-index elements of "p" policy rules. So make sure your object
     *         is the 1-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    getAllObjects() {
        return this.getAllNamedObjects('p');
    }
    /**
     * getAllNamedObjects gets the list of objects that show up in the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return all the objects in policy rules of the ptype type. It actually
     *         collects the 1-index elements of the policy rules. So make sure
     *         your object is the 1-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    getAllNamedObjects(ptype) {
        return this.model.getValuesForFieldInPolicy('p', ptype, 1);
    }
    /**
     * getAllActions gets the list of actions that show up in the current policy.
     *
     * @return all the actions in "p" policy rules. It actually collects
     *         the 2-index elements of "p" policy rules. So make sure your action
     *         is the 2-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    getAllActions() {
        return this.getAllNamedActions('p');
    }
    /**
     * GetAllNamedActions gets the list of actions that show up in the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return all the actions in policy rules of the ptype type. It actually
     *         collects the 2-index elements of the policy rules. So make sure
     *         your action is the 2-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    getAllNamedActions(ptype) {
        return this.model.getValuesForFieldInPolicy('p', ptype, 2);
    }
    /**
     * getAllRoles gets the list of roles that show up in the current policy.
     *
     * @return all the roles in "g" policy rules. It actually collects
     *         the 1-index elements of "g" policy rules. So make sure your
     *         role is the 1-index element, like (sub, role).
     *         Duplicates are removed.
     */
    getAllRoles() {
        return this.getAllNamedRoles('g');
    }
    /**
     * getAllNamedRoles gets the list of roles that show up in the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @return all the subjects in policy rules of the ptype type. It actually
     *         collects the 0-index elements of the policy rules. So make
     *         sure your subject is the 0-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    getAllNamedRoles(ptype) {
        return this.model.getValuesForFieldInPolicy('g', ptype, 1);
    }
    /**
     * getPolicy gets all the authorization rules in the policy.
     *
     * @return all the "p" policy rules.
     */
    getPolicy() {
        return this.getNamedPolicy('p');
    }
    /**
     * getFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "p" policy rules.
     */
    getFilteredPolicy(fieldIndex, ...fieldValues) {
        return this.getFilteredNamedPolicy('p', fieldIndex, ...fieldValues);
    }
    /**
     * getNamedPolicy gets all the authorization rules in the named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return the "p" policy rules of the specified ptype.
     */
    getNamedPolicy(ptype) {
        return this.model.getPolicy('p', ptype);
    }
    /**
     * getFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "p" policy rules of the specified ptype.
     */
    getFilteredNamedPolicy(ptype, fieldIndex, ...fieldValues) {
        return this.model.getFilteredPolicy('p', ptype, fieldIndex, ...fieldValues);
    }
    /**
     * getGroupingPolicy gets all the role inheritance rules in the policy.
     *
     * @return all the "g" policy rules.
     */
    getGroupingPolicy() {
        return this.getNamedGroupingPolicy('g');
    }
    /**
     * getFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value "" means not to match this field.
     * @return the filtered "g" policy rules.
     */
    getFilteredGroupingPolicy(fieldIndex, ...fieldValues) {
        return this.getFilteredNamedGroupingPolicy('g', fieldIndex, ...fieldValues);
    }
    /**
     * getNamedGroupingPolicy gets all the role inheritance rules in the policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @return the "g" policy rules of the specified ptype.
     */
    getNamedGroupingPolicy(ptype) {
        return this.model.getPolicy('g', ptype);
    }
    /**
     * getFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "g" policy rules of the specified ptype.
     */
    getFilteredNamedGroupingPolicy(ptype, fieldIndex, ...fieldValues) {
        return this.model.getFilteredPolicy('g', ptype, fieldIndex, ...fieldValues);
    }
    /**
     * hasPolicy determines whether an authorization rule exists.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return whether the rule exists.
     */
    hasPolicy(...params) {
        return this.hasNamedPolicy('p', ...params);
    }
    /**
     * hasNamedPolicy determines whether a named authorization rule exists.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return whether the rule exists.
     */
    hasNamedPolicy(ptype, ...params) {
        return this.model.hasPolicy('p', ptype, params);
    }
    /**
     * addPolicy adds an authorization rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    addPolicy(...params) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.addNamedPolicy('p', ...params);
        });
    }
    /**
     * addNamedPolicy adds an authorization rule to the current named policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    addNamedPolicy(ptype, ...params) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.addPolicyInternal('p', ptype, params);
        });
    }
    /**
     * removePolicy removes an authorization rule from the current policy.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    removePolicy(...params) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.removeNamedPolicy('p', ...params);
        });
    }
    /**
     * removeFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    removeFilteredPolicy(fieldIndex, ...fieldValues) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.removeFilteredNamedPolicy('p', fieldIndex, ...fieldValues);
        });
    }
    /**
     * removeNamedPolicy removes an authorization rule from the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    removeNamedPolicy(ptype, ...params) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.removePolicyInternal('p', ptype, params);
        });
    }
    /**
     * removeFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    removeFilteredNamedPolicy(ptype, fieldIndex, ...fieldValues) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.removeFilteredPolicyInternal('p', ptype, fieldIndex, fieldValues);
        });
    }
    /**
     * hasGroupingPolicy determines whether a role inheritance rule exists.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return whether the rule exists.
     */
    hasGroupingPolicy(...params) {
        return this.hasNamedGroupingPolicy('g', ...params);
    }
    /**
     * hasNamedGroupingPolicy determines whether a named role inheritance rule exists.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return whether the rule exists.
     */
    hasNamedGroupingPolicy(ptype, ...params) {
        return this.model.hasPolicy('g', ptype, params);
    }
    /**
     * addGroupingPolicy adds a role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    addGroupingPolicy(...params) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.addNamedGroupingPolicy('g', ...params);
        });
    }
    /**
     * addNamedGroupingPolicy adds a named role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    addNamedGroupingPolicy(ptype, ...params) {
        return __awaiter(this, void 0, void 0, function* () {
            const ruleadded = yield this.addPolicyInternal('g', ptype, params);
            if (this.autoBuildRoleLinks) {
                this.buildRoleLinks();
            }
            return ruleadded;
        });
    }
    /**
     * removeGroupingPolicy removes a role inheritance rule from the current policy.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    removeGroupingPolicy(...params) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.removeNamedGroupingPolicy('g', ...params);
        });
    }
    /**
     * removeFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    removeFilteredGroupingPolicy(fieldIndex, ...fieldValues) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.removeFilteredNamedGroupingPolicy('g', fieldIndex, ...fieldValues);
        });
    }
    /**
     * removeNamedGroupingPolicy removes a role inheritance rule from the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    removeNamedGroupingPolicy(ptype, ...params) {
        return __awaiter(this, void 0, void 0, function* () {
            const ruleRemoved = yield this.removePolicyInternal('g', ptype, params);
            if (this.autoBuildRoleLinks) {
                this.buildRoleLinks();
            }
            return ruleRemoved;
        });
    }
    /**
     * removeFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    removeFilteredNamedGroupingPolicy(ptype, fieldIndex, ...fieldValues) {
        return __awaiter(this, void 0, void 0, function* () {
            const ruleRemoved = yield this.removeFilteredPolicyInternal('g', ptype, fieldIndex, fieldValues);
            if (this.autoBuildRoleLinks) {
                this.buildRoleLinks();
            }
            return ruleRemoved;
        });
    }
    /**
     * addFunction adds a customized function.
     * @param name custom function name
     * @param func function
     */
    addFunction(name, func) {
        this.fm.addFunction(name, func);
    }
}
exports.ManagementEnforcer = ManagementEnforcer;
