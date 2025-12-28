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

**Core idea of project** is improving safety of apps that use sql databases and informing service about detections for it to perform action

DataFilter **is not able** to fully protect service, input escaping is still reqiured and highly recommended!

---

## Project functionality

function **strSQLICheck**

- Analyses provided data using basic-heuristic and pattern-based startegy
- Generates report upon returning that includes useful and overall safety information about provided data

---

## Repository structure

Below the repository directory tree is provided (without cache files like `__pycache__`):

```
    DataFilter
    ├── docs
    │   └── docs.odt
    ├── testapps
    │   ├── appSQLInoFiltering
    │   │   ├── app.py
    │   │   ├── database.db
    │   │   └── requirements.txt
    │   └── appSQLIwithFiltering
    │       ├── app.py
    │       ├── database.db
    │       ├── DataFilter.py
    │       └── requirements.txt
    ├── DataFilter.py
    ├── LICENCE
    └── README.md


```

- **`testapps`** — 2 test apps without input escaping: **appSQLInoFiltering** with DataFilter not being used, **appSQLIwithFiltering** with DataFilter used; start them with commands below, ensure you are in app's directory
```
python -m pip install pip update
python -m pip install requirements.txt
python app.py
``` 
After that use any sqli testing utility you like (for example sqlmap)

---

## Expected behavior

- **Normal user**: interacts with service without any problem, may sometimes trigger filter, for example by using ' or " in password when registering
- **Attacker**: tries to use sqli -> filter detects sqli usage -> (programmer defined behaviour) service takes action (for example temporary ban if 3+ sqli usage tries detected)

---

## Full documentation

You can find full documentation in docs.odt file [here](https://github.com/Mavment/DataFilter/tree/master/docs)

Full documentation includes expected behaviour of data checker, strategies used, report structure and a lot more!

---

## Contacts

- Its well-known that no contraption is perfect and DataFilter is not an exception, you may ask me freely if you have any questions/suggestions, i'll answer whenever i'll be free (usually not more then 1 business day)

Thanks for using **DataFilter**!