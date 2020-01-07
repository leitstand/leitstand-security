# Leitstand User Repository Database Model

This document describes the tables, including their relations, forming the _Leitstand User Repository Database Model_, 
which is a relational database model.

The Leitstand user repository tables are located in the `auth` database schema.

## Entity Relationship Diagram

## Tables

### `userdata` Table
The `userdata` table stores the user profile data.

#### Columns

| Column       | Type          | Description                                                    |
|:-------------|:--------------|:---------------------------------------------------------------|
| ID           | INT8          | Contiguous number as primary key.                              |
| UUID         | CHARACTER(36) | Unique account ID in UUIDv4 format.                            |
| USERID       | VARCHAR(128)  | User account ID, also the login ID.                            |
| EMAIL        | VARCHAR(128)  | The user's email address.                                      |
| GIVENNAME    | VARCHAR(128)  | The user's first name.                                         |
| SURNAME      | VARCHAR(128)  | The user's last name.                                          |
| ITERATIONS   | INT4          | Number of iterations used when the password hash was computed. | 
| SALT64       | VARCHAR       | Base64-encoded password salt value.                            |
| PASS64       | VARCHAR       | Base64-encoded password hash value.                            |
| TOKENTTL     | INT4          | Time-to-live duration of an access token issued for this user. |
| TOKENTTLUNIT | VARCHAR(16)   | Time-to-live duration unit.                                    |
| TSMODIFIED   | TIMESTAMP     | Last-modification timestamp.                                   |
| TSCREATED    | TIMESTAMP     | Creation timestamp.                                            |

Supported token time-to-live units are
- `SECONDS`,
- `MINUTES`,
- `HOURS`, and
- `DAYS`

#### Primary Key
The `ID` column forms the primary key.

#### Unique Constraints
The `userdata` table has two unique constraints:
- The `UUID` column value must be unique for all user profiles.
- The `USERID` column value must be unique for all user profiles.

### `userrole` Table
The `userrole` table stores all pre-defined roles.

#### Columns

| Column      | Type          | Description                       |
|:------------|:--------------|:----------------------------------|
| ID          | INT8          | Contiguous number as primary key. |
| NAME        | VARCHAR(128)  | The role name.                    |
| DESCRIPTION | VARCHAR(1024) | Optional role description.        |
| TSMODIFIED  | TIMESTAMP     | Last-modification timestamp.      |
| TSCREATED   | TIMESTAMP     | Creation timestamp.               |

#### Primary Key
The `ID` column forms the primary key.

#### Unique Constraints
The `NAME` column must be unique for all roles.

### `userdata_userrole` Table
The `userdata_userrole` table connects users with their assigned roles and vice versa.

#### Columns

| Column      | Type | Description                       |
|:------------|:-----|:----------------------------------|
| USERDATA_ID | INT8 | Reference to the userdata record. |
| USERROLE_ID | INT8 | Reference to the userrole record. |

#### Primary Key
The `USERDATA_ID` and `USERROLE_ID` columns form the primary key.

#### Foreign Keys
The `userdata_userrole` table has two foreign keys.
- The `userdata_id` column refers to the `ID` column in the `userdata` table.
- The `userrole_id` column refers to the `ID` column in the `userrole` table.



