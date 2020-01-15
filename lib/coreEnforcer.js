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
const expression_eval_1 = require("expression-eval");
const _ = require("lodash");
const effect_1 = require("./effect");
const model_1 = require("./model");
const rbac_1 = require("./rbac");
const util_1 = require("./util");
const casbin_1 = require("./casbin");
const log_1 = require("./log");
/**
 * CoreEnforcer defines the core functionality of an enforcer.
 */
class CoreEnforcer {
    constructor() {
        this.watcher = null;
    }
    initialize() {
        this.rm = new rbac_1.DefaultRoleManager(10);
        this.eft = new effect_1.DefaultEffector();
        this.watcher = null;
        this.enabled = true;
        this.autoSave = true;
        this.autoBuildRoleLinks = true;
    }
    /**
     * loadModel reloads the model from the model CONF file.
     * Because the policy is attached to a model,
     * so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
     */
    loadModel() {
        this.model = casbin_1.newModel();
        this.model.loadModel(this.modelPath);
        this.model.printModel();
        this.fm = model_1.FunctionMap.loadFunctionMap();
    }
    /**
     * getModel gets the current model.
     *
     * @return the model of the enforcer.
     */
    getModel() {
        return this.model;
    }
    /**
     * setModel sets the current model.
     *
     * @param m the model.
     */
    setModel(m) {
        this.model = m;
        this.fm = model_1.FunctionMap.loadFunctionMap();
    }
    /**
     * getAdapter gets the current adapter.
     *
     * @return the adapter of the enforcer.
     */
    getAdapter() {
        return this.adapter;
    }
    /**
     * setAdapter sets the current adapter.
     *
     * @param adapter the adapter.
     */
    setAdapter(adapter) {
        this.adapter = adapter;
    }
    /**
     * setWatcher sets the current watcher.
     *
     * @param watcher the watcher.
     */
    setWatcher(watcher) {
        this.watcher = watcher;
        watcher.setUpdateCallback(() => __awaiter(this, void 0, void 0, function* () { return yield this.loadPolicy(); }));
    }
    /**
     * setRoleManager sets the current role manager.
     *
     * @param rm the role manager.
     */
    setRoleManager(rm) {
        this.rm = rm;
    }
    /**
     * setEffector sets the current effector.
     *
     * @param eft the effector.
     */
    setEffector(eft) {
        this.eft = eft;
    }
    /**
     * clearPolicy clears all policy.
     */
    clearPolicy() {
        this.model.clearPolicy();
    }
    /**
     * loadPolicy reloads the policy from file/database.
     */
    loadPolicy() {
        return __awaiter(this, void 0, void 0, function* () {
            this.model.clearPolicy();
            yield this.adapter.loadPolicy(this.model);
            this.model.printPolicy();
            if (this.autoBuildRoleLinks) {
                this.buildRoleLinks();
            }
        });
    }
    /**
     * loadFilteredPolicy reloads a filtered policy from file/database.
     *
     * @param filter the filter used to specify which type of policy should be loaded.
     */
    loadFilteredPolicy(filter) {
        return __awaiter(this, void 0, void 0, function* () {
            this.model.clearPolicy();
            yield this.adapter.loadFilteredPolicy(this.model, filter);
            this.model.printPolicy();
            if (this.autoBuildRoleLinks) {
                this.buildRoleLinks();
            }
            return true;
        });
    }
    /**
     * isFiltered returns true if the loaded policy has been filtered.
     *
     * @return if the loaded policy has been filtered.
     */
    isFiltered() {
        if (this.adapter.isFiltered) {
            return this.adapter.isFiltered();
        }
        return false;
    }
    /**
     * savePolicy saves the current policy (usually after changed with
     * Casbin API) back to file/database.
     */
    savePolicy() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.isFiltered()) {
                throw new Error('cannot save a filtered policy');
            }
            const flag = yield this.adapter.savePolicy(this.model);
            if (!flag) {
                return false;
            }
            if (this.watcher) {
                return yield this.watcher.update();
            }
            return true;
        });
    }
    /**
     * enableEnforce changes the enforcing state of Casbin, when Casbin is
     * disabled, all access will be allowed by the enforce() function.
     *
     * @param enable whether to enable the enforcer.
     */
    enableEnforce(enable) {
        this.enabled = enable;
    }
    /**
     * enableLog changes whether to print Casbin log to the standard output.
     *
     * @param enable whether to enable Casbin's log.
     */
    enableLog(enable) {
        log_1.getLogger().enableLog(enable);
    }
    /**
     * enableAutoSave controls whether to save a policy rule automatically to
     * the adapter when it is added or removed.
     *
     * @param autoSave whether to enable the AutoSave feature.
     */
    enableAutoSave(autoSave) {
        this.autoSave = autoSave;
    }
    /**
     * enableAutoBuildRoleLinks controls whether to save a policy rule
     * automatically to the adapter when it is added or removed.
     *
     * @param autoBuildRoleLinks whether to automatically build the role links.
     */
    enableAutoBuildRoleLinks(autoBuildRoleLinks) {
        this.autoBuildRoleLinks = autoBuildRoleLinks;
    }
    /**
     * buildRoleLinks manually rebuild the
     * role inheritance relations.
     */
    buildRoleLinks() {
        // error intentionally ignored
        this.rm.clear();
        this.model.buildRoleLinks(this.rm);
    }
    /**
     * enforce decides whether a "subject" can access a "object" with
     * the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param rvals the request needs to be mediated, usually an array
     *              of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    enforce(...rvals) {
        if (!this.enabled) {
            return true;
        }
        const functions = {};
        this.fm.getFunctions().forEach((value, key) => {
            functions[key] = value;
        });
        const astMap = this.model.model.get('g');
        if (astMap) {
            astMap.forEach((value, key) => {
                const rm = value.rm;
                functions[key] = util_1.generateGFunction(rm);
            });
        }
        // @ts-ignore
        const expString = this.model.model.get('m').get('m').value;
        if (!expString) {
            throw new Error('model is undefined');
        }
        const expression = expression_eval_1.compile(expString);
        let policyEffects;
        let matcherResults;
        // @ts-ignore
        const policyLen = this.model.model.get('p').get('p').policy.length;
        if (policyLen !== 0) {
            policyEffects = new Array(policyLen);
            matcherResults = new Array(policyLen);
            for (let i = 0; i < policyLen; i++) {
                // @ts-ignore
                const pvals = this.model.model.get('p').get('p').policy[i];
                // logPrint('Policy Rule: ', pvals);
                const parameters = {};
                // @ts-ignore
                this.model.model.get('r').get('r').tokens.forEach((token, j) => {
                    parameters[token] = rvals[j];
                });
                // @ts-ignore
                this.model.model.get('p').get('p').tokens.forEach((token, j) => {
                    parameters[token] = pvals[j];
                });
                const result = expression(Object.assign(Object.assign({}, parameters), functions));
                switch (typeof result) {
                    case 'boolean':
                        if (!result) {
                            policyEffects[i] = effect_1.Effect.Indeterminate;
                            continue;
                        }
                        break;
                    case 'number':
                        if (result === 0) {
                            policyEffects[i] = effect_1.Effect.Indeterminate;
                            continue;
                        }
                        else {
                            matcherResults[i] = result;
                        }
                        break;
                    default:
                        throw new Error('matcher result should be boolean or number');
                }
                if (_.has(parameters, 'p_eft')) {
                    const eft = _.get(parameters, 'p_eft');
                    if (eft === 'allow') {
                        policyEffects[i] = effect_1.Effect.Allow;
                    }
                    else if (eft === 'deny') {
                        policyEffects[i] = effect_1.Effect.Deny;
                    }
                    else {
                        policyEffects[i] = effect_1.Effect.Indeterminate;
                    }
                }
                else {
                    policyEffects[i] = effect_1.Effect.Allow;
                }
                // @ts-ignore
                if (this.model.model.get('e').get('e').value === 'priority(p_eft) || deny') {
                    break;
                }
            }
        }
        else {
            policyEffects = new Array(1);
            matcherResults = new Array(1);
            const parameters = {};
            // @ts-ignore
            this.model.model.get('r').get('r').tokens.forEach((token, j) => {
                parameters[token] = rvals[j];
            });
            // @ts-ignore
            this.model.model.get('p').get('p').tokens.forEach((token) => {
                parameters[token] = '';
            });
            const result = expression(Object.assign(Object.assign({}, parameters), functions));
            // logPrint(`Result: ${result}`);
            if (result) {
                policyEffects[0] = effect_1.Effect.Allow;
            }
            else {
                policyEffects[0] = effect_1.Effect.Indeterminate;
            }
        }
        // logPrint(`Rule Results: ${policyEffects}`);
        // @ts-ignore
        const res = this.eft.mergeEffects(this.model.model.get('e').get('e').value, policyEffects, matcherResults);
        // only generate the request --> result string if the message
        // is going to be logged.
        if (log_1.getLogger().isEnable()) {
            let reqStr = 'Request: ';
            for (let i = 0; i < rvals.length; i++) {
                if (i !== rvals.length - 1) {
                    reqStr += `${rvals[i]}, `;
                }
                else {
                    reqStr += rvals[i];
                }
            }
            reqStr += ` ---> ${res}`;
            log_1.logPrint(reqStr);
        }
        return res;
    }
}
exports.CoreEnforcer = CoreEnforcer;
