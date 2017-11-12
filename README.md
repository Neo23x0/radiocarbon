# RadioCarbon
Leak File Analyzer

# What is RadioCarbon?

Typically you get leaked credentials that look like the list in the following screenshot. They consist of email addresses or user names, cleartext passwords or password hashes. 

![Typical leak](https://raw.githubusercontent.com/Neo23x0/radiocarbon/master/screens/leak1.png)

The problem with those leaked files is, that you have no idea how relevant they are and who to inform about the leak. 

- They could be 15 years old and obsolete
- They typically don't indicates the origin of the leaked credentials

# The Idea

The idea behind RadioCarbon uses the fact that the users of the service provide indicators for the origin and the age of the leak by choosing certain passwords or email addresses. 

- Users include the current year in their passwords (e.g. `stephan2017`, `Mercedes17!`, `pass2016`)
- Users typically don't include a year in the password that is in the future (e.g. `pass2022`, `website2045`)
- Users include the name of the website/service in their passwords (e.g. `website1234`, `pass4website`)
- Users use one time email addresses for the registration (e.g. `website-12@mailinator.com`, `mail4website@maildrop.cc`)
- Users can use the "+" character to easily create [new email aliases](https://fieldguide.gizmodo.com/how-to-use-the-infinite-number-of-email-addresses-gmail-1609458192) for certain purposes (e.g. `john.smith+onlineshop.com@gmail.com`)

# The Inner Workings

RadioCarbon uses extractions based on regular expressions, statistics and filter mechanisms to generate the report panels.

1. Reads password lists from the `./passlists` sub folder (used for filtering)
2. Reads the leak file
3. Extracts `words`, 2 and 4 character `numbers`, top level domains `tlds` and one time emails `onetimemails` from the leak
4. Processing the lists - removes standard passwords from `words`, removing numbers that can't be years, prepedning `(20)` for better readbility, removing `tlds` from `words`
5. Prints the result tables

# Issues

- If the user field contains a nickname and no email address, the region analysis fails
- If the password field contains a password hash and not a clear text password, the analysis is strongly hindered

# Prepare a Leak File for Analysis

If a leak file doesn't contain th clear text passwords, use [john the cracker](http://www.openwall.com/john/) or another password cracker to pre-process the file before using it as input for RadioCarbon. 

# Screenshots

![Example1](https://raw.githubusercontent.com/Neo23x0/radiocarbon/master/screens/radiocarbon1.png)

![Example2](https://raw.githubusercontent.com/Neo23x0/radiocarbon/master/screens/radiocarbon2.png)

![Example3](https://raw.githubusercontent.com/Neo23x0/radiocarbon/master/screens/radiocarbon3.png)
