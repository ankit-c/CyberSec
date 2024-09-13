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
