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
const coreEnforcer_1 = require("./coreEnforcer");
/**
 * InternalEnforcer = CoreEnforcer + Internal API.
 */
class InternalEnforcer extends coreEnforcer_1.CoreEnforcer {
    /**
     * addPolicyInternal adds a rule to the current policy.
     */
    addPolicyInternal(sec, ptype, rule) {
        return __awaiter(this, void 0, void 0, function* () {
            const ruleAdded = this.model.addPolicy(sec, ptype, rule);
            if (!ruleAdded) {
                return ruleAdded;
            }
            if (this.adapter && this.autoSave) {
                try {
                    yield this.adapter.addPolicy(sec, ptype, rule);
                }
                catch (e) {
                    if (e.message !== 'not implemented') {
                        throw e;
                    }
                }
                if (this.watcher) {
                    // error intentionally ignored
                    this.watcher.update();
                }
            }
            return ruleAdded;
        });
    }
    /**
     * removePolicyInternal removes a rule from the current policy.
     */
    removePolicyInternal(sec, ptype, rule) {
        return __awaiter(this, void 0, void 0, function* () {
            const ruleRemoved = this.model.removePolicy(sec, ptype, rule);
            if (!ruleRemoved) {
                return ruleRemoved;
            }
            if (this.adapter && this.autoSave) {
                try {
                    yield this.adapter.removePolicy(sec, ptype, rule);
                }
                catch (e) {
                    if (e.message !== 'not implemented') {
                        throw e;
                    }
                }
                if (this.watcher) {
                    // error intentionally ignored
                    this.watcher.update();
                }
            }
            return ruleRemoved;
        });
    }
    /**
     * removeFilteredPolicyInternal removes rules based on field filters from the current policy.
     */
    removeFilteredPolicyInternal(sec, ptype, fieldIndex, fieldValues) {
        return __awaiter(this, void 0, void 0, function* () {
            const ruleRemoved = this.model.removeFilteredPolicy(sec, ptype, fieldIndex, ...fieldValues);
            if (!ruleRemoved) {
                return ruleRemoved;
            }
            if (this.adapter && this.autoSave) {
                try {
                    yield this.adapter.removeFilteredPolicy(sec, ptype, fieldIndex, ...fieldValues);
                }
                catch (e) {
                    if (e.message !== 'not implemented') {
                        throw e;
                    }
                }
                if (this.watcher) {
                    // error intentionally ignored
                    this.watcher.update();
                }
            }
            return ruleRemoved;
        });
    }
}
exports.InternalEnforcer = InternalEnforcer;
