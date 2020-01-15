"use strict";
// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the 'License');
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an 'AS IS' BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
Object.defineProperty(exports, "__esModule", { value: true });
const _ = require("lodash");
const fs = require("fs");
// escapeAssertion escapes the dots in the assertion,
// because the expression evaluation doesn't support such variable names.
function escapeAssertion(s) {
    s = s.replace(/r\./g, 'r_');
    s = s.replace(/p\./g, 'p_');
    return s;
}
exports.escapeAssertion = escapeAssertion;
// removeComments removes the comments starting with # in the text.
function removeComments(s) {
    const pos = s.indexOf('#');
    return pos > -1 ? _.trim(s.slice(0, pos)) : s;
}
exports.removeComments = removeComments;
// arrayEquals determines whether two string arrays are identical.
function arrayEquals(a, b) {
    return _.isEqual(a, b);
}
exports.arrayEquals = arrayEquals;
// array2DEquals determines whether two 2-dimensional string arrays are identical.
function array2DEquals(a, b) {
    return _.isEqual(a, b);
}
exports.array2DEquals = array2DEquals;
// arrayRemoveDuplicates removes any duplicated elements in a string array.
function arrayRemoveDuplicates(s) {
    return _.uniq(s);
}
exports.arrayRemoveDuplicates = arrayRemoveDuplicates;
// arrayToString gets a printable string for a string array.
function arrayToString(a) {
    return _.join(a, ', ');
}
exports.arrayToString = arrayToString;
// paramsToString gets a printable string for variable number of parameters.
function paramsToString(...v) {
    return _.join(v, ', ');
}
exports.paramsToString = paramsToString;
// setEquals determines whether two string sets are identical.
function setEquals(a, b) {
    return _.isEqual(_.sortedUniq(a), _.sortedUniq(b));
}
exports.setEquals = setEquals;
// readFile return a promise for readFile.
function readFile(path, encoding) {
    return new Promise((resolve, reject) => {
        fs.readFile(path, encoding || 'utf8', (error, data) => {
            if (error) {
                reject(error);
            }
            resolve(data);
        });
    });
}
exports.readFile = readFile;
// writeFile return a promise for writeFile.
function writeFile(path, file, encoding) {
    return new Promise((resolve, reject) => {
        fs.writeFile(path, file, encoding || 'utf8', (error) => {
            if (error) {
                reject(error);
            }
            resolve(true);
        });
    });
}
exports.writeFile = writeFile;
