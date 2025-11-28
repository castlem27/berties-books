# Berties Books

Sample code for Dynamic Web Applications module.

Uses node.js with Express and EJS.

To install and run:

npm install
node index.js

Dotenv

To protect sensitive database credentials, I implemented the dotenv module.
I created a .env file in the project root which stores my database username, password, host, and database name.
These values are then loaded at the top of app.js using:

require('dotenv').config();


The database connection pool now uses:

user: process.env.DB_USER,
password: process.env.DB_PASS,
database: process.env.DB_NAME


The .env file is added to .gitignore, ensuring that no private credentials are pushed to GitHub.


Audit

I added an audit logging feature to record all login attempts.
A new MySQL table called login_audit stores the username, whether the attempt was successful (1) or failed (0), and a timestamp.

Inside the existing /loggedin route, I inserted a simple line to record each login attempt:

db.query("INSERT INTO login_audit (username, success) VALUES (?,?)",
         [req.body.username, 1 or 0]);


A new route /users/audit was also created to display the full audit log using an EJS page.

This allows the system to track all successful and failed logins in a clear and simple way.


Restricted access

Only two pages in my project has restricted access:

/addbook – This page can only be accessed if the user is logged in.
If someone who is not logged in tries to open it, they are redirected to the login page.

/users/list - This page cannot be accessed by non logged in users.

All other pages in the site are not restricted and can be accessed without logging in.


Validation

For the registration form, I applied validation to the following fields:

Email – checked to make sure the user enters a valid email address.

Username – checked to ensure it is between a set minimum and maximum length.

Password – checked to make sure it meets the required length.

These validations were added to prevent users from entering incorrect or incomplete information. They help keep the data stored in the database consistent and stop users from registering with invalid details.

I did not apply validation to fields like first name or last name beyond basic requirements, because these fields can vary more between users, and they do not need strict rules for the system to work.

Sanitisation

I applied sanitisation to the text fields in the registration form, such as the first name, last name, username, and email. These fields were sanitised on the server to remove any unwanted HTML or script tags before storing the data. This helps prevent XSS (cross-site scripting) and makes sure that only clean text is saved in the database.

I did not apply sanitisation to the password field. This is because sanitising a password would change the characters the user typed, which would cause login issues and reduce password security. The password is only validated for length and then hashed, so there is no need to sanitise it.  