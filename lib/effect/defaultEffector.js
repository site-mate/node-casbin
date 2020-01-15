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
const effector_1 = require("./effector");
/**
 * DefaultEffector is default effector for Casbin.
 */
class DefaultEffector {
    /**
     * mergeEffects merges all matching results collected by the enforcer into a single decision.
     * @param {string} expr
     * @param {Effect[]} effects
     * @param {number[]} results
     * @returns {boolean}
     */
    mergeEffects(expr, effects, results) {
        let result = false;
        if (expr === 'some(where (p_eft == allow))') {
            result = effects.some(n => n === effector_1.Effect.Allow);
        }
        else if (expr === '!some(where (p_eft == deny))') {
            result = !effects.some(n => n === effector_1.Effect.Deny);
        }
        else if (expr === 'some(where (p_eft == allow)) && !some(where (p_eft == deny))') {
            result = false;
            for (const eft of effects) {
                if (eft === effector_1.Effect.Allow) {
                    result = true;
                }
                else if (eft === effector_1.Effect.Deny) {
                    result = false;
                    break;
                }
            }
        }
        else if (expr === 'priority(p_eft) || deny') {
            result = effects.some(n => n !== effector_1.Effect.Indeterminate && n === effector_1.Effect.Allow);
        }
        else {
            throw new Error('unsupported effect');
        }
        return result;
    }
}
exports.DefaultEffector = DefaultEffector;
