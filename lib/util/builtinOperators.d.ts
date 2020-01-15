import * as rbac from '../rbac';
declare function keyMatchFunc(...args: any[]): boolean;
declare function keyMatch2Func(...args: any[]): boolean;
declare function keyMatch3Func(...args: any[]): boolean;
declare function regexMatchFunc(...args: any[]): boolean;
declare function ipMatchFunc(...args: any[]): boolean;
declare function generateGFunction(rm: rbac.RoleManager): any;
export { keyMatchFunc, keyMatch2Func, keyMatch3Func, regexMatchFunc, ipMatchFunc, generateGFunction };
