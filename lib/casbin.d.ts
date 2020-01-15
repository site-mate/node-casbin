import { Enforcer } from './enforcer';
import { Model } from './model';
/**
 * newModel creates a model.
 */
declare function newModel(...text: string[]): Model;
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
declare function newEnforcer(...params: any[]): Promise<Enforcer>;
export { newEnforcer, newModel };
