# SQL Injection Demo

An interactive web application built to visually demonstrate how an SQL injection attack works, and how parameterized queries completely mitigate it. Built with **Python**, **Flask**, and **SQLite**.

---

## The Concept

This tool provides a side-by-side comparison of a vulnerable login system vs. a secure login system. Both systems use an identical user database and identical frontend templates, differing only in how they handle SQL query construction.

- **Vulnerable End (f-strings)**
  Directly interpolates raw user input into the SQL query string. Attackers can provide input (like single quotes) to "break out" of the expected data context and execute arbitrary SQL logic (e.g. `' OR '1'='1' --`).

- **Secure End (Parameterized Queries)**
  Passes a pre-compiled query structure to the database driver with `?` parameter placeholders. The database treats the supplied user input strictly as literal data rather than executable SQL code, completely destroying the attacker's ability to manipulate the SQL syntax.

## Requirements

- Python 3.11+
- No additional database software required (uses Python's built-in `sqlite3`).

## Usage

**1. Install Dependencies & Start Server:**
```bash
pip install -r requirements.txt
python app.py
```

*Note: The script automatically creates the `users.db` SQLite database with seeded demo credentials upon its first run (`admin`, `alice`, `bob`).*

**2. Access the Dashboard:**
Open your browser and navigate to:
```
http://localhost:5007
```

**3. Explore the Demonstration:**
Use the provided quick-action buttons to instantly populate the form fields with either valid credentials or classic payload injections. Both the `/vulnerable` and `/secure` pages dynamically display the final transformed SQL query executed on the backend, clearly demonstrating the mechanics of the bypass and the block in real-time.
