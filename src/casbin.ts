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

import { Enforcer } from './enforcer';
import { getLogger } from './log';
import { Model } from './model';

/**
 * newModel creates a model.
 */
function newModel(...text: string[]): Model {
  const m = new Model();

  if (text.length === 2) {
    if (text[0] !== '') {
      m.loadModel(text[0]);
    }
  } else if (text.length === 1) {
    m.loadModelFromText(text[0]);
  } else if (text.length !== 0) {
    throw new Error('Invalid parameters for model.');
  }

  return m;
}

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

async function newEnforcer(...params: any[]): Promise<Enforcer> {
  const e = new Enforcer();

  let parsedParamLen = 0;
  if (params.length >= 1) {
    const enableLog = params[params.length - 1];
    if (typeof enableLog === 'boolean') {
      getLogger().enableLog(enableLog);
      parsedParamLen++;
    }
  }

  if (params.length - parsedParamLen === 3) {
    if (typeof params[0] === 'string') {
      if (typeof params[1] === 'string') {
        await e.initWithFile(params[0].toString(), params[1].toString());
      } else {
        await e.initWithAdapter(params[0].toString(), params[1], params[2]);
      }
    } else {
      if (typeof params[1] === 'string') {
        throw new Error('Invalid parameters for enforcer.');
      } else {
        await e.initWithModelAndAdapter(params[0], params[1]);
      }
    }
  } else if (params.length - parsedParamLen === 2) {
    if (typeof params[0] === 'string') {
      if (typeof params[1] === 'string') {
        await e.initWithFile(params[0].toString(), params[1].toString());
      } else {
        await e.initWithAdapter(params[0].toString(), params[1]);
      }
    } else {
      if (typeof params[1] === 'string') {
        throw new Error('Invalid parameters for enforcer.');
      } else {
        await e.initWithModelAndAdapter(params[0], params[1]);
      }
    }
  } else if (params.length - parsedParamLen === 1) {
    if (typeof params[0] === 'string') {
      await e.initWithFile(params[0], '');
    } else {
      // @ts-ignore
      await e.initWithModelAndAdapter(params[0], null);
    }
  } else if (params.length === parsedParamLen) {
    await e.initWithFile('', '');
  } else {
    throw new Error('Invalid parameters for enforcer.');
  }

  return e;
}

export {
  newEnforcer,
  newModel
};
