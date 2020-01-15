## Reason for fork
On every check we are getting a filtered policy specific to that user. This clears the existing local policy. This means there is no reason to fetch the full policy on startup. 
This fork implements the option to create a new enforcer and passing in a filter, so a filtered policy will be fetched instead, greatly reducing initialization time.

node-Casbin
====
[![NPM version][npm-image]][npm-url]
[![NPM download][download-image]][download-url]
[![codebeat badge](https://codebeat.co/badges/c17c9ee1-da42-4db3-8047-9574ad2b23b1)](https://codebeat.co/projects/github-com-casbin-node-casbin-master)
[![Build Status](https://travis-ci.org/casbin/node-casbin.svg?branch=master)](https://travis-ci.org/casbin/node-casbin)
[![Coverage Status](https://coveralls.io/repos/github/casbin/node-casbin/badge.svg?branch=master)](https://coveralls.io/github/casbin/node-casbin?branch=master)
[![Release](https://img.shields.io/github/release/casbin/node-casbin.svg)](https://github.com/casbin/node-casbin/releases/latest)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/casbin/lobby)
[![Patreon](https://img.shields.io/badge/patreon-donate-yellow.svg)](http://www.patreon.com/yangluo)

[npm-image]: https://img.shields.io/npm/v/casbin.svg?style=flat-square
[npm-url]: https://npmjs.org/package/casbin
[download-image]: https://img.shields.io/npm/dm/casbin.svg?style=flat-square
[download-url]: https://npmjs.org/package/casbin

**News**: still worry about how to write the correct node-Casbin policy? ``Casbin online editor`` is coming to help! Try it at: http://casbin.org/editor/

![casbin Logo](casbin-logo.png)

node-Casbin is a powerful and efficient open-source access control library for Node.JS projects. It provides support for enforcing authorization based on various [access control models](https://en.wikipedia.org/wiki/Computer_security_model).

## All the languages supported by Casbin:

[![golang](https://casbin.org/img/langs/golang.png)](https://github.com/casbin/casbin) | [![java](https://casbin.org/img/langs/java.png)](https://github.com/casbin/jcasbin) | [![nodejs](https://casbin.org/img/langs/nodejs.png)](https://github.com/casbin/node-casbin) | [![php](https://casbin.org/img/langs/php.png)](https://github.com/php-casbin/php-casbin)
----|----|----|----
[Casbin](https://github.com/casbin/casbin) | [jCasbin](https://github.com/casbin/jcasbin) | [node-Casbin](https://github.com/casbin/node-casbin) | [PHP-Casbin](https://github.com/php-casbin/php-casbin)
production-ready | production-ready | production-ready | production-ready

[![python](https://casbin.org/img/langs/python.png)](https://github.com/casbin/pycasbin) | [![delphi](https://casbin.org/img/langs/delphi.png)](https://github.com/casbin4d/Casbin4D) | [![dotnet](https://casbin.org/img/langs/dotnet.png)](https://github.com/Devolutions/casbin-net) | [![rust](https://casbin.org/img/langs/rust.png)](https://github.com/Devolutions/casbin-rs)
----|----|----|----
[PyCasbin](https://github.com/casbin/pycasbin) | [Casbin4D](https://github.com/casbin4d/Casbin4D) | [Casbin-Net](https://github.com/Devolutions/casbin-net) | [Casbin-RS](https://github.com/Devolutions/casbin-rs)
production-ready | experimental | WIP | WIP

## Installation

```
npm install casbin --save
```

## Get started

1. Initialize a new node-Casbin enforcer with a model file and a policy file:

    ```typescript
    import casbin from 'casbin';
    const enforcer = await casbin.newEnforcer('path/to/model.conf', 'path/to/policy.csv');
    ```
    
    Note: you can also initialize an enforcer with policy in DB instead of file, see [Persistence](#policy-persistence) section for details.

2. Add an enforcement hook into your code right before the access happens:

    ```typescript
    const sub = 'alice'; // the user that wants to access a resource.
    const obj = 'data1'; // the resource that is going to be accessed.
    const act = 'read'; // the operation that the user performs on the resource.

    if (enforcer.enforce(sub, obj, act) == true) {
        // permit alice to read data1
    } else {
        // deny the request, show an error
    }
    ```

3. Besides the static policy file, node-Casbin also provides API for permission management at run-time. For example, You can get all the roles assigned to a user as below:

    ```typescript
    const roles = enforcer.getRoles('alice');
    ```
    
    See [Policy management APIs](#policy-management) for more usage.

4. Please refer to the [src/test](https://github.com/casbin/node-casbin/tree/master/test) package for more usage.

## Table of contents

- [Supported models](#supported-models)
- [How it works?](#how-it-works)
- [Features](#features)
- [Documentation](#documentation)
- [Online editor](#online-editor)
- [Tutorials](#tutorials)
- [Policy management](#policy-management)
- [Policy persistence](#policy-persistence)
- [Role manager](#role-manager)
- [Examples](#examples)
- [Middlewares](#middlewares)
- [Our adopters](#our-adopters)

## Supported models

1. [**ACL (Access Control List)**](https://en.wikipedia.org/wiki/Access_control_list)
2. **ACL with [superuser](https://en.wikipedia.org/wiki/Superuser)**
3. **ACL without users**: especially useful for systems that don't have authentication or user log-ins.
3. **ACL without resources**: some scenarios may target for a type of resources instead of an individual resource by using permissions like ``write-article``, ``read-log``. It doesn't control the access to a specific article or log.
4. **[RBAC (Role-Based Access Control)](https://en.wikipedia.org/wiki/Role-based_access_control)**
5. **RBAC with resource roles**: both users and resources can have roles (or groups) at the same time.
6. **RBAC with domains/tenants**: users can have different role sets for different domains/tenants.
7. **[ABAC (Attribute-Based Access Control)](https://en.wikipedia.org/wiki/Attribute-Based_Access_Control)**: syntax sugar like ``resource.Owner`` can be used to get the attribute for a resource.
8. **[RESTful](https://en.wikipedia.org/wiki/Representational_state_transfer)**: supports paths like ``/res/*``, ``/res/:id`` and HTTP methods like ``GET``, ``POST``, ``PUT``, ``DELETE``.
9. **Deny-override**: both allow and deny authorizations are supported, deny overrides the allow.
10. **Priority**: the policy rules can be prioritized like firewall rules.

## How it works?

In node-Casbin, an access control model is abstracted into a CONF file based on the **PERM metamodel (Policy, Effect, Request, Matchers)**. So switching or upgrading the authorization mechanism for a project is just as simple as modifying a configuration. You can customize your own access control model by combining the available models. For example, you can get RBAC roles and ABAC attributes together inside one model and share one set of policy rules.

The most basic and simplest model in node-Casbin is ACL. ACL's model CONF is:

```ini
# Request definition
[request_definition]
r = sub, obj, act

# Policy definition
[policy_definition]
p = sub, obj, act

# Policy effect
[policy_effect]
e = some(where (p.eft == allow))

# Matchers
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

An example policy for ACL model is like:

```
p, alice, data1, read
p, bob, data2, write
```

It means:

- alice can read data1
- bob can write data2

## Features

What node-Casbin does:

1. enforce the policy in the classic ``{subject, object, action}`` form or a customized form as you defined, both allow and deny authorizations are supported.
2. handle the storage of the access control model and its policy.
3. manage the role-user mappings and role-role mappings (aka role hierarchy in RBAC).
4. support built-in superuser like ``root`` or ``administrator``. A superuser can do anything without explict permissions.
5. multiple built-in operators to support the rule matching. For example, ``keyMatch`` can map a resource key ``/foo/bar`` to the pattern ``/foo*``.

What node-Casbin does NOT do:

1. authentication (aka verify ``username`` and ``password`` when a user logs in)
2. manage the list of users or roles. I believe it's more convenient for the project itself to manage these entities. Users usually have their passwords, and node-Casbin is not designed as a password container. However, node-Casbin stores the user-role mapping for the RBAC scenario. 

## Documentation

https://casbin.org/docs/en/overview

## Online editor

You can also use the online editor (http://casbin.org/editor/) to write your node-Casbin model and policy in your web browser. It provides functionality such as ``syntax highlighting`` and ``code completion``, just like an IDE for a programming language.

## Tutorials

https://casbin.org/docs/en/tutorials

## Policy management

node-Casbin provides two sets of APIs to manage permissions:

- [Management API](https://casbin.org/docs/en/management-api): the primitive API that provides full support for node-Casbin policy management.
- [RBAC API](https://casbin.org/docs/en/management-api): a more friendly API for RBAC. This API is a subset of Management API. The RBAC users could use this API to simplify the code.

We also provide a web-based UI for model management and policy management:

![model editor](https://hsluoyz.github.io/casbin/ui_model_editor.png)

![policy editor](https://hsluoyz.github.io/casbin/ui_policy_editor.png)

## Policy persistence

https://casbin.org/docs/en/adapters

## Role manager

https://casbin.org/docs/en/role-managers

## Examples

Model | Model file | Policy file
----|------|----
ACL | [basic_model.conf](https://github.com/casbin/node-casbin/blob/master/examples/basic_model.conf) | [basic_policy.csv](https://github.com/casbin/node-casbin/blob/master/examples/basic_policy.csv)
ACL with superuser | [basic_model_with_root.conf](https://github.com/casbin/node-casbin/blob/master/examples/basic_with_root_model.conf) | [basic_policy.csv](https://github.com/casbin/node-casbin/blob/master/examples/basic_policy.csv)
ACL without users | [basic_model_without_users.conf](https://github.com/casbin/node-casbin/blob/master/examples/basic_without_users_model.conf) | [basic_policy_without_users.csv](https://github.com/casbin/node-casbin/blob/master/examples/basic_without_users_policy.csv)
ACL without resources | [basic_model_without_resources.conf](https://github.com/casbin/node-casbin/blob/master/examples/basic_without_resources_model.conf) | [basic_policy_without_resources.csv](https://github.com/casbin/node-casbin/blob/master/examples/basic_without_resources_policy.csv)
RBAC | [rbac_model.conf](https://github.com/casbin/node-casbin/blob/master/examples/rbac_model.conf)  | [rbac_policy.csv](https://github.com/casbin/node-casbin/blob/master/examples/rbac_policy.csv)
RBAC with resource roles | [rbac_model_with_resource_roles.conf](https://github.com/casbin/node-casbin/blob/master/examples/rbac_with_resource_roles_model.conf)  | [rbac_policy_with_resource_roles.csv](https://github.com/casbin/node-casbin/blob/master/examples/rbac_with_resource_roles_policy.csv)
RBAC with domains/tenants | [rbac_model_with_domains.conf](https://github.com/casbin/node-casbin/blob/master/examples/rbac_with_domains_model.conf)  | [rbac_policy_with_domains.csv](https://github.com/casbin/node-casbin/blob/master/examples/rbac_with_domains_policy.csv)
ABAC | [abac_model.conf](https://github.com/casbin/node-casbin/blob/master/examples/abac_model.conf)  | N/A
RESTful | [keymatch_model.conf](https://github.com/casbin/node-casbin/blob/master/examples/keymatch_model.conf)  | [keymatch_policy.csv](https://github.com/casbin/node-casbin/blob/master/examples/keymatch_policy.csv)
Deny-override | [rbac_model_with_deny.conf](https://github.com/casbin/node-casbin/blob/master/examples/rbac_with_deny_model.conf)  | [rbac_policy_with_deny.csv](https://github.com/casbin/node-casbin/blob/master/examples/rbac_with_deny_policy.csv)
Priority | [priority_model.conf](https://github.com/casbin/node-casbin/blob/master/examples/priority_model.conf)  | [priority_policy.csv](https://github.com/casbin/node-casbin/blob/master/examples/priority_policy.csv)

## Middlewares

Authz middlewares for web frameworks: https://casbin.org/docs/en/middlewares

## Our adopters

https://casbin.org/docs/en/adopters

## License

This project is licensed under the [Apache 2.0 license](LICENSE).

## Contact

If you have any issues or feature requests, please contact us. PR is welcomed.
- https://github.com/casbin/node-casbin/issues
- hsluoyz@gmail.com
- Tencent QQ group: [546057381](//shang.qq.com/wpa/qunwpa?idkey=8ac8b91fc97ace3d383d0035f7aa06f7d670fd8e8d4837347354a31c18fac885)
