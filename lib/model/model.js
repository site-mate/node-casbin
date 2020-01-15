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
const _ = require("lodash");
const util = require("../util");
const config_1 = require("../config");
const assertion_1 = require("./assertion");
const log_1 = require("../log");
const sectionNameMap = {
    r: 'request_definition',
    p: 'policy_definition',
    g: 'role_definition',
    e: 'policy_effect',
    m: 'matchers'
};
class Model {
    /**
     * constructor is the constructor for Model.
     */
    constructor() {
        this.model = new Map();
    }
    loadAssertion(cfg, sec, key) {
        // console.log('loadAssertion: ', sec, key);
        const secName = sectionNameMap[sec];
        const value = cfg.getString(`${secName}::${key}`);
        return this.addDef(sec, key, value);
    }
    getKeySuffix(i) {
        if (i === 1) {
            return '';
        }
        return _.toString(i);
    }
    loadSection(cfg, sec) {
        // console.log('loadSection: ', sec);
        let i = 1;
        for (;;) {
            if (!this.loadAssertion(cfg, sec, sec + this.getKeySuffix(i))) {
                break;
            }
            else {
                i++;
            }
        }
    }
    // addDef adds an assertion to the model.
    addDef(sec, key, value) {
        // console.log('addDef: ', sec, key. value);
        if (value === '') {
            return false;
        }
        const ast = new assertion_1.Assertion();
        ast.key = key;
        ast.value = value;
        if (sec === 'r' || sec === 'p') {
            const tokens = value.split(', ');
            for (let i = 0; i < tokens.length; i++) {
                tokens[i] = key + '_' + tokens[i];
            }
            ast.tokens = tokens;
        }
        else {
            ast.value = util.removeComments(util.escapeAssertion(value));
        }
        const nodeMap = this.model.get(sec);
        if (nodeMap) {
            nodeMap.set(key, ast);
        }
        else {
            const assertionMap = new Map();
            assertionMap.set(key, ast);
            this.model.set(sec, assertionMap);
        }
        return true;
    }
    // loadModel loads the model from model CONF file.
    loadModel(path) {
        // console.log('loadModel: ', path);
        const cfg = config_1.Config.newConfig(path);
        this.loadSection(cfg, 'r');
        this.loadSection(cfg, 'p');
        this.loadSection(cfg, 'e');
        this.loadSection(cfg, 'm');
        this.loadSection(cfg, 'g');
    }
    // loadModelFromText loads the model from the text.
    loadModelFromText(text) {
        const cfg = config_1.Config.newConfigFromText(text);
        this.loadSection(cfg, 'r');
        this.loadSection(cfg, 'p');
        this.loadSection(cfg, 'e');
        this.loadSection(cfg, 'm');
        this.loadSection(cfg, 'g');
    }
    // printModel prints the model to the log.
    printModel() {
        log_1.logPrint('Model:');
        this.model.forEach((value, key) => {
            value.forEach((ast, astKey) => {
                log_1.logPrint(`${key}.${astKey}: ${ast.value}`);
            });
        });
    }
    // buildRoleLinks initializes the roles in RBAC.
    buildRoleLinks(rm) {
        const astMap = this.model.get('g');
        if (!astMap) {
            return;
        }
        astMap.forEach(value => {
            value.buildRoleLinks(rm);
        });
    }
    // clearPolicy clears all current policy.
    clearPolicy() {
        this.model.forEach((value, key) => {
            if (key === 'p' || key === 'g') {
                value.forEach(ast => {
                    ast.policy = [];
                });
            }
        });
    }
    // getPolicy gets all rules in a policy.
    getPolicy(sec, key) {
        const policy = [];
        const ast = (this.model.get(sec) || new Map()).get(key);
        if (ast) {
            policy.push(...ast.policy);
        }
        return policy;
    }
    // hasPolicy determines whether a model has the specified policy rule.
    hasPolicy(sec, key, rule) {
        const ast = (this.model.get(sec) || new Map()).get(key);
        if (!ast) {
            return false;
        }
        return ast.policy.some((n) => util.arrayEquals(n, rule));
    }
    // addPolicy adds a policy rule to the model.
    addPolicy(sec, key, rule) {
        if (!this.hasPolicy(sec, key, rule)) {
            const ast = (this.model.get(sec) || new Map()).get(key);
            if (!ast) {
                return false;
            }
            ast.policy.push(rule);
            return true;
        }
        return false;
    }
    // removePolicy removes a policy rule from the model.
    removePolicy(sec, key, rule) {
        if (this.hasPolicy(sec, key, rule)) {
            const ast = (this.model.get(sec) || new Map()).get(key);
            if (!ast) {
                return true;
            }
            ast.policy = _.filter(ast.policy, r => !util.arrayEquals(rule, r));
            return true;
        }
        return false;
    }
    // getFilteredPolicy gets rules based on field filters from a policy.
    getFilteredPolicy(sec, key, fieldIndex, ...fieldValues) {
        const res = [];
        const ast = (this.model.get(sec) || new Map()).get(key);
        if (!ast) {
            return res;
        }
        for (const rule of ast.policy) {
            let matched = true;
            for (let i = 0; i < fieldValues.length; i++) {
                const fieldValue = fieldValues[i];
                if (fieldValue !== '' && rule[fieldIndex + i] !== fieldValue) {
                    matched = false;
                    break;
                }
            }
            if (matched) {
                res.push(rule);
            }
        }
        return res;
    }
    // removeFilteredPolicy removes policy rules based on field filters from the model.
    removeFilteredPolicy(sec, key, fieldIndex, ...fieldValues) {
        const res = [];
        let bool = false;
        const ast = (this.model.get(sec) || new Map()).get(key);
        if (!ast) {
            return bool;
        }
        for (const rule of ast.policy) {
            let matched = true;
            for (let i = 0; i < fieldValues.length; i++) {
                const fieldValue = fieldValues[i];
                if (fieldValue !== '' && rule[fieldIndex + i] !== fieldValue) {
                    matched = false;
                    break;
                }
            }
            if (matched) {
                bool = true;
            }
            else {
                res.push(rule);
            }
        }
        ast.policy = res;
        return bool;
    }
    // getValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
    getValuesForFieldInPolicy(sec, key, fieldIndex) {
        const values = [];
        const ast = (this.model.get(sec) || new Map()).get(key);
        if (!ast) {
            return values;
        }
        return util.arrayRemoveDuplicates(ast.policy.map((n) => n[fieldIndex]));
    }
    // printPolicy prints the policy to log.
    printPolicy() {
        log_1.logPrint('Policy:');
        this.model.forEach((map, key) => {
            if (key === 'p' || key === 'g') {
                map.forEach(ast => {
                    log_1.logPrint(`key, : ${ast.value}, : , ${ast.policy}`);
                });
            }
        });
    }
}
exports.Model = Model;
