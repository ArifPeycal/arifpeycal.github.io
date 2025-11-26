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

## Lab 02: SQL injection vulnerability allowing login bypass
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
