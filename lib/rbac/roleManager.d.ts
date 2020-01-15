export interface RoleManager {
    clear(): void;
    addLink(name1: string, name2: string, ...domain: string[]): void;
    deleteLink(name1: string, name2: string, ...domain: string[]): void;
    hasLink(name1: string, name2: string, ...domain: string[]): boolean;
    getRoles(name: string, ...domain: string[]): string[];
    getUsers(name: string, ...domain: string[]): string[];
    printRoles(): void;
}
