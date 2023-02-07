# Leitstand Security User Interface

The _Leitstand Security User Interface_ adds user, role and access key management views to the _Leitstand Administration Console_.



# Access Keys

Let's walk through the most important access key views.

The **Access Keys** view lists all access keys.

![Empty access keys list](./doc/assets/no_accesskeys.png "No access keys defined") 


Click the **Add access key** button to create a new access key.

![Add new access key](./doc/assets/new_accesskey.png "New access key") 

Assign a unique name, 
select the [resource scopes](../leitstand-auth/README.md) the access key is allowed to access and
add an optional description.

Click the **Create access key** button to create the access key.

![Created access key](./doc/assets/created_accesskey.png "Created access key") 

Click the **Copy access key** button to copy the generated access key into the clipboard.

**NOTE:** The access key cannot be viewed again after closing this view.

The access key list shows the newly created access key.

Click the access key to inspect the access key details. 
It shows the access key name, accessible resource scopes and the access key description.

![Access key details](./doc/assets/accesskey_details.png "Access key details") 

The access key is immutable. Only the description can be amended. 

Click the **Revoke access key** button to invalidate the access key.

![Confirm revoke](./doc/assets/confirm_revoke.png "Confirm access key revokation") 

Click the **Confirm** button to revoke the access key.

In case an access key was revoked accidentally it can be restored with the access key validator.

Click **Access Key Validator** to open the access key validator and paste the access key into the textarea.

![Access key validator](./doc/assets/accesskey_validator.png "Access key validator")

Click the **Validate access key** button to validate the access key. 
The access key validator allows restoring a valid access key.

![Revoked access key](./doc/assets/restore_revoked_accesskey.png "Valid but revoked access key") 

Click the **Restore access key** button to restore the access key.

The access key validator also displays the status of valid access keys.

![Valid access key](./doc/assets/valid_accesskey.png "Valid access key") 


# Users and Roles