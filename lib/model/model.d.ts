import * as rbac from '../rbac';
import { Assertion } from './assertion';
export declare class Model {
    model: Map<string, Map<string, Assertion>>;
    /**
     * constructor is the constructor for Model.
     */
    constructor();
    private loadAssertion;
    private getKeySuffix;
    private loadSection;
    addDef(sec: string, key: string, value: string): boolean;
    loadModel(path: string): void;
    loadModelFromText(text: string): void;
    printModel(): void;
    buildRoleLinks(rm: rbac.RoleManager): void;
    clearPolicy(): void;
    getPolicy(sec: string, key: string): string[][];
    hasPolicy(sec: string, key: string, rule: string[]): boolean;
    addPolicy(sec: string, key: string, rule: string[]): boolean;
    removePolicy(sec: string, key: string, rule: string[]): boolean;
    getFilteredPolicy(sec: string, key: string, fieldIndex: number, ...fieldValues: string[]): string[][];
    removeFilteredPolicy(sec: string, key: string, fieldIndex: number, ...fieldValues: string[]): boolean;
    getValuesForFieldInPolicy(sec: string, key: string, fieldIndex: number): string[];
    printPolicy(): void;
}
