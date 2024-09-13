# Microsoft SQL Server (MSSQL)

#### Connect Using Windows Authentication
```
sqlcmd -S .\SQLEXPRESS
```

#### Connect Using SQL Server Authentication
```
sqlcmd -S .\SQLEXPRESS -U sa -P Password123
```

Use ```-d``` option to specify a database to connect to by default. For example:
```
sqlcmd -S .\SQLEXPRESS -d YourDatabase
```

Use ```-Q``` option to execute a query on connection. For example:
```
sqlcmd -S .\SQLEXPRESS -U sa -P YourPassword123 -Q "SELECT name FROM sys.databases
```

#### List all the databases
```
SELECT name FROM sys.databases;
GO
```

#### Select the database
```
USE <DATABASE NAME>
GO
```

#### Check for schemas
```
SELECT TABLE_SCHEMA, TABLE_NAME FROM information_schema.tables WHERE table_type = 'BASE TABLE';
GO
```

#### Show tables
```
SELECT table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE';
GO
```

#### Select table
```
SELECT * FROM <TableName>;
GO
```

#### SQL Server Logins

Accounts that can connect to the SQL Server instance.
```
SELECT name, type_desc, create_date, modify_date FROM sys.server_principals WHERE type IN ('S', 'U', 'G', 'K');
GO
```

- ```'S'``` for SQL Server login
- ```'U'``` for Windows login
- ```'G'``` for Windows group
- ```'K'``` for Azure Active Directory (AAD) login


#### Dynamic Management Views (DMVs)

Monitor sessions:
```
SELECT session_id, login_name, status  FROM sys.dm_exec_sessions;
GO
```

#### Monitor currently running queries:
```
SELECT sqltext.text, req.start_time FROM sys.dm_exec_requests req CROSS APPLY sys.dm_exec_sql_text(req.sql_handle) AS sqltext;
GO
```
