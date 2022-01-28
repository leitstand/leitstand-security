# Leitstand User Repository

The _Leitstand User Repository_ stores Leitstand user profiles.

It is recommended to delegate user authorization to an OpenID/Connect-compliant authorization service.
In such a setup Leitstand merely stores the user profile information obtained from the OpenId/Connect user endpoint in the user repository.

The user repository includes user role management support in case authorization is not delegated to a specialized authorization service.

## Scopes, Roles and User Profiles.

Leitstand REST resources are assigned to different _scopes_.
A resource can be assigned to multiple scopes and the same scope can be assigned to different resources to be specific.
A user is allowed to access a resource if they are allowed to access at least one of the scopes assigned to the REST resource.

The Leitstand user repository allows defining roles. 
A role conceptionally describes a function in an organization and groups the scopes required to fulfill this function.
A user can have multiple roles within the organization and a the same role can be assigned to multiple users.

The relationship between user profiles, roles and scopes is illustrated below.


![Leistand User Repository Entities](doc/assets/user_repo_entities.png "Leitstand User Repository Entities") 


### Scopes

A scope is a structured string to group REST resources. 
For example the `ivt` scope includes all inventory resources, while `ivt.element` includes all element inventory resources.

### Role

A role describes a function in an organization. 

A role consists of:

- a unique immutable role ID in UUIDv4 format
- a unique name
- a set of scopes the role can access and
- an optional description.

The Leitstand UI and administration REST API allows creating and removing roles.

### User Profile

The user profile consists of

- the unique immutable user account ID in UUIDv4 format
- the unique user name, which is used to login to Leitstand
- the user's email address
- the user's first and last name
- the user's roles
- the user's password

Passwords are stored as salted hash values using the [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) hash function.
The applied number of iterations for the hash computation is stored in the user entity, which allows to increase the number of iterations if needed. Salt and password hash are stored Base64-encoded.




