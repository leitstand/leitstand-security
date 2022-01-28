# Leitstand Authentication and Authorization API

The _Leitstand Authentication and Authorization API_ provides means to obtain information about the authenticated user and to protect Leitstand resources from unauthorized access. In addition, the API allows creating _temporary_ access tokens to authorize requests between different Leitstand services.

## Resource Scopes

Leitstand resources can be assigned to different resource scopes.
A scope in turn can contain multiple resources.

A scope is a structured string and uses a dot as delimiter between a scope and is sub-scopes.
For example, _ivt_ and _ivt.element_ are both valid scopes. _ivt_ is a top-level scope and represents the entire Leitstand inventory, whereas _ivt.element_ encompasses the element inventory resources only.

The `@Scopes` annotation allows declaring the scopes of a resources. 
Scopes can be declared on type and method level.
The scopes defined on method level extend the scopes defined on type level.

The example below lists the `ElementSettingsResource` and its scopes.

```Java
@Resource
@Scopes({"ivt","ivt.element"})
public class ElementSettingsResource{

 @GET
 @Path("/{element:"+UUID_PATTERN+"}/settings")
 @Scopes({"ivt.read"})
 public ElementSettings getElementSettings(@Valid @PathParam("element") ElementId element){
   ...
 }
 @PUT
 @Path("/{element:"+UUID_PATTERN+"}/settings")
 public Response storeElementSettings(@Valid @PathParam("element") ElementId element, 
                                      @Valid ElementSettings settings){
 ...
 }
 ...
}
```

The `ElementSettingsResource` belongs to the _ivt_ and _ivt.element_ scopes. 
The `getElementSettings` _additionally_ belongs to the _ivt.read_ scope.


Users are granted access to resource scopes. 
Thus users with access to the _ivt_ and _ivt.element_ scopes can read and store element settings, 
whereas users with access to `ivt.read` scope are only allowed to read the element settings.


## UserContext

The `UserContext` is a request-scoped CDI-managed bean and provides information about the authenticated user 
and the scopes the user is allowed to access. 

## API Access Keys
API access keys allow Leitstand components to create a temporary access key to authorize service calls.
A scheduled job, for example, creates temporary access tokens to execute its tasks on behalf of the user who created the job.