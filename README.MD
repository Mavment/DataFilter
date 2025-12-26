# DataFilter

## Contents

1. [About project](#About-project)
2. [Project functionality](#Project-functionality)
3. [Repository structure](#Repository-structure)
4. [Expected behavior](#Expected-behavior)
5. [Full documentation](#Full-documentation)
6. [Contacts](#Contacts)

---

## About project

**DataFilter** is a single-file library written on Python used for:

1. Checking if data includes sqli techniques usage
2. Providing detailed information about safety of data
3. Helping to temporary/permamently block potential attackers, improving safety

---

## Project functionality

function **strSQLICheck**

- Analyses provided data using basic-heuristic and pattern-based startegy
- Generates report upon returning that includes useful and overall safety information about provided data

## Repository structure

Below is the directory tree is provided(without cache files like `__pycache__`):

```
    DataFilter
    ├── docs
    │   └── docs.odt
    ├── testapps
    │   ├── appSQLInoFiltering
    │       ├──
    │   └── appSQLIwithFiltering
    │       ├──
    ├── DataFilter.py
    └── README.md


```

- **`testapps`** — 2 test apps without input escaping: **appSQLInoFiltering** without DataFilter usage, **appSQLIwithFiltering** with DataFilter used; start them with ```python app.py``` command and use any sqli testing utility you like (for example sqlmap)

---

## Expected behavior

- **Normal user** interacts with service without any problem, may sometimes trigger filter, for example using ' or " in password when registering
- **Attacker** tries to use sqli -> Filter detects sqli usage -> (programmer defined) service takes action (for example temporary ban if 3+ sqli usage tries detected) 

---

## Full documentation

You can find full documentation in docs.odt file [here](placeholder)

Full documentation includes expected behaviour of data checker, strategies used, report structure and a lot more!

---

## Contacts

- Its well-known that no contraption is perfect and DataFilter is not an exception, you may ask me freely if you have any questions/suggestions, i'll answer whenever i'll be free (usually not more then 1 business day)

- Thanks for using **DataFilter**!