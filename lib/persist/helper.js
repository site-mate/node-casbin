"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class Helper {
    static loadPolicyLine(line, model) {
        if (line === '' || line.charAt(0) === '#') {
            return;
        }
        const tokens = line.split(', ').map(n => n.trim());
        const key = tokens[0];
        const sec = key.substring(0, 1);
        const item = model.model.get(sec);
        if (!item) {
            return;
        }
        const policy = item.get(key);
        if (!policy) {
            return;
        }
        policy.policy.push(tokens.slice(1));
    }
}
exports.Helper = Helper;
