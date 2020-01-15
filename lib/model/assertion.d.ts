import * as rbac from '../rbac';
export declare class Assertion {
    key: string;
    value: string;
    tokens: string[];
    policy: string[][];
    rm: rbac.RoleManager;
    /**
     * constructor is the constructor for Assertion.
     */
    constructor();
    buildRoleLinks(rm: rbac.RoleManager): void;
}
