"use strict";
// Copyright 2019 The Casbin Authors. All Rights Reserved.
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
const enforcer_1 = require("./enforcer");
const log_1 = require("./log");
const model_1 = require("./model");
/**
 * newModel creates a model.
 */
function newModel(...text) {
    const m = new model_1.Model();
    if (text.length === 2) {
        if (text[0] !== '') {
            m.loadModel(text[0]);
        }
    }
    else if (text.length === 1) {
        m.loadModelFromText(text[0]);
    }
    else if (text.length !== 0) {
        throw new Error('Invalid parameters for model.');
    }
    return m;
}
exports.newModel = newModel;
/**
 * newEnforcer creates an enforcer via file or DB.
 *
 * File:
 * ```js
 * const e = new Enforcer('path/to/basic_model.conf', 'path/to/basic_policy.csv');
 * ```
 *
 * MySQL DB:
 * ```js
 * const a = new MySQLAdapter('mysql', 'mysql_username:mysql_password@tcp(127.0.0.1:3306)/');
 * const e = new Enforcer('path/to/basic_model.conf', a);
 * ```
 *
 * @param params
 */
function newEnforcer(...params) {
    return __awaiter(this, void 0, void 0, function* () {
        const e = new enforcer_1.Enforcer();
        let parsedParamLen = 0;
        if (params.length >= 1) {
            const enableLog = params[params.length - 1];
            if (typeof enableLog === 'boolean') {
                log_1.getLogger().enableLog(enableLog);
                parsedParamLen++;
            }
        }
        if (params.length - parsedParamLen === 3) {
            if (typeof params[0] === 'string') {
                if (typeof params[1] === 'string') {
                    yield e.initWithFile(params[0].toString(), params[1].toString());
                }
                else {
                    yield e.initWithAdapter(params[0].toString(), params[1], params[2]);
                }
            }
            else {
                if (typeof params[1] === 'string') {
                    throw new Error('Invalid parameters for enforcer.');
                }
                else {
                    yield e.initWithModelAndAdapter(params[0], params[1]);
                }
            }
        }
        else if (params.length - parsedParamLen === 2) {
            if (typeof params[0] === 'string') {
                if (typeof params[1] === 'string') {
                    yield e.initWithFile(params[0].toString(), params[1].toString());
                }
                else {
                    yield e.initWithAdapter(params[0].toString(), params[1]);
                }
            }
            else {
                if (typeof params[1] === 'string') {
                    throw new Error('Invalid parameters for enforcer.');
                }
                else {
                    yield e.initWithModelAndAdapter(params[0], params[1]);
                }
            }
        }
        else if (params.length - parsedParamLen === 1) {
            if (typeof params[0] === 'string') {
                yield e.initWithFile(params[0], '');
            }
            else {
                // @ts-ignore
                yield e.initWithModelAndAdapter(params[0], null);
            }
        }
        else if (params.length === parsedParamLen) {
            yield e.initWithFile('', '');
        }
        else {
            throw new Error('Invalid parameters for enforcer.');
        }
        return e;
    });
}
exports.newEnforcer = newEnforcer;
