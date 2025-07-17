#snowflake_utils.py
import os
import snowflake.connector
from typing import List, Dict, Any, Tuple, Union
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def get_private_key():
    """
    Parse the private key from environment variable
    """
    private_key_content = os.getenv("SNOWFLAKE_PRIVATE_KEY")
    if private_key_content:
        p_key = load_pem_private_key(
            private_key_content.encode(),
            password=None,
            backend=default_backend()
        )
        return p_key
    else:
        raise ValueError("Private key not found in environment variables")


def _query_snowflake(query: str, params: Tuple = ()) -> Union[List[Dict[str, Any]], Dict[str, str]]:
    """
    Internal helper to execute a query on Snowflake without performing access checks.
    This is used for metadata queries (e.g., fetching user department or allowed tables).
    """
    conn = None
    cursor = None
    try:
        conn = snowflake.connector.connect(
            user=os.getenv("SNOWFLAKE_USER"),
            account=os.getenv("SNOWFLAKE_ACCOUNT"),
            private_key=get_private_key(),  # Use private key instead of password
            warehouse="PROD_QUERY_WH",
            database="ATI_PROD_V1",
            schema="AGENTAI",
        )
        cursor = conn.cursor()
        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        return results
    except Exception as e:
        return {"error": str(e)}
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def get_allowed_tables_for_user(user_email: str) -> List[str]:
    """
    Returns a list of table names the user is allowed to access,
    based on the user's department mapping and department access rules.
    Supports users with multiple departments (comma-separated).
    """
    # Define the two tables that should be accessible to all users.
    always_allowed_tables = ["USERROLE", "ROLE"]

    # Query to get the user's department(s)
    dept_query = """SELECT "dept" FROM "USERROLE" WHERE "empname" = %s"""
    dept_result = _query_snowflake(dept_query, params=(user_email,))

    # If no department is found, return only the always allowed tables.
    if not dept_result or "error" in dept_result[0] or not dept_result[0].get("dept"):
        return always_allowed_tables

    # Extract and handle multiple departments
    dept_list = [dept.strip() for dept in dept_result[0]["dept"].split(",")]

    allowed_tables_set = set()

    for dept in dept_list:
        # Query to get the allowed tables for each department
        access_query = """SELECT "table_access" FROM "ROLE" WHERE "dept" = %s"""
        access_result = _query_snowflake(access_query, params=(dept,))

        if access_result and "error" not in access_result[0] and access_result[0].get("table_access"):
            # Extract and handle multiple tables per department
            tables = [table.strip() for table in access_result[0]["table_access"].split(",")]
            allowed_tables_set.update(tables)

    # Add the always allowed tables to the user's allowed tables
    allowed_tables_set.update(always_allowed_tables)

    return list(allowed_tables_set)



def extract_table_names(query: str) -> List[str]:
    """
    Extract real table names from a SQL query, excluding any CTEs and ignoring SQL functions like EXTRACT(... FROM ...).
    """
    import re

    # Normalize query
    query = query.strip().replace("\n", " ").replace("\r", " ")

    # Prevent FROM detection inside EXTRACT(...)
    extract_pattern = re.compile(r'EXTRACT\s*\(\s*\w+\s+FROM\s+[^)]+\)', re.IGNORECASE)
    matches = extract_pattern.findall(query)
    for match in matches:
        query = query.replace(match, match.replace("FROM", "__FROM_PLACEHOLDER__"))

    # --- NEW: Get ALL CTE names ---
    cte_name_pattern = re.compile(r'WITH\s+(.*?)\s+SELECT', re.IGNORECASE | re.DOTALL)
    all_cte_names = []

    # Find all WITH <CTE> AS (...) , <CTE2> AS (...) style
    with_split = re.split(r'\bWITH\b', query, flags=re.IGNORECASE)
    if len(with_split) > 1:
        cte_block = with_split[1]
        cte_defs = re.split(r'\b(?<!\)),\s*([a-zA-Z0-9_"]+)\s+AS\s*\(', cte_block)
        for i in range(1, len(cte_defs), 2):  # only names at odd indices
            cte_name = cte_defs[i].replace('"', '').strip()
            all_cte_names.append(cte_name)

    # Also pick up any lone <name> AS ( in case above missed some
    fallback_cte_pattern = re.compile(r'([\w"]+)\s+AS\s*\(', re.IGNORECASE)
    fallback_ctes = [cte.strip().replace('"', '') for cte in fallback_cte_pattern.findall(query)]
    for cte in fallback_ctes:
        if cte not in all_cte_names:
            all_cte_names.append(cte)

    # --- Extract actual table names ---
    table_pattern = re.compile(r'\b(?:FROM|JOIN)\s+([a-zA-Z0-9_."`]+)', re.IGNORECASE)
    all_tables = table_pattern.findall(query)

    cleaned_tables = [
        tbl.replace('"', '').replace("'", "").strip()
        for tbl in all_tables
        if tbl.replace('"', '').strip().upper() not in [cte.upper() for cte in all_cte_names]
    ]

    return list(set(cleaned_tables))





def query_snowflake(query: str, user_email: str, params: Tuple = ()) -> Union[List[Dict[str, Any]], Dict[str, str]]:
    """
    Executes a query on Snowflake but first checks if the user has permission to access the referenced tables.
    """
    conn = None
    cursor = None
    try:
        allowed_tables = get_allowed_tables_for_user(user_email)
        if not allowed_tables:
            return {"error": "Access Denied: You do not have permission to access any tables."}

        # Extract table names from the query
        tables_in_query = extract_table_names(query)

        # Check each table for access permissions
        for table in tables_in_query:
            if table.upper() not in [t.upper() for t in allowed_tables]:
                # Get the specific role needed for this table
                role_query = """SELECT "dept" FROM "ROLE" WHERE "table_access" LIKE %s"""
                role_result = _query_snowflake(role_query, params=(f"%{table}%",))

                if role_result and "error" not in role_result[0] and role_result[0].get("dept"):
                    required_role = role_result[0]["dept"]
                    return {"error": f"Access Denied: You do not have permission to role: \"{required_role}\""}
                else:
                    return {"error": f"Access Denied: You do not have permission to access table: {table}"}

        # Proceed with query execution
        conn = snowflake.connector.connect(
            user=os.getenv("SNOWFLAKE_USER"),
            account=os.getenv("SNOWFLAKE_ACCOUNT"),
            private_key=get_private_key(),
            warehouse="PROD_QUERY_WH",
            database="ATI_PROD_V1",
            schema="AGENTAI",
        )
        cursor = conn.cursor()
        cursor.execute(query, params)

        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        return results

    except Exception as e:
        return {"error": str(e)}
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


SCHEMA_TYPE_OVERRIDES = {
    "PO_DETAILS": {
        "COMPANY_ID": "NUMERIC_ID(3)"  # Clearly indicates it's an ID with numbers
    }
}


def get_schema_details(user_email: str) -> Union[Dict[str, List[Tuple[str, str]]], Dict[str, str]]:
    """
    Fetch schema details dynamically from Snowflake and return the full schema,
    without filtering based on allowed tables.
    """
    conn = None
    cursor = None
    try:
        conn = snowflake.connector.connect(
            user=os.getenv("SNOWFLAKE_USER"),
            account=os.getenv("SNOWFLAKE_ACCOUNT"),
            private_key=get_private_key(),  # Use private key instead of password
            warehouse="PROD_QUERY_WH",
            database="ATI_PROD_V1",
            schema="AGENTAI",
        )
        cursor = conn.cursor()

        # Fetch table names from Snowflake.
        cursor.execute("SHOW TABLES;")
        tables = [row[1] for row in cursor.fetchall()]

        # Fetch column details for each table.
        schema_details: Dict[str, List[Tuple[str, str]]] = {}
        for table in tables:
            cursor.execute(f"DESCRIBE TABLE {table};")
            columns = []
            for row in cursor.fetchall():
                column_name = row[0]
                data_type = row[1]

                # Check if there's an override for this table/column combination
                if table.upper() in SCHEMA_TYPE_OVERRIDES:
                    if column_name.upper() in SCHEMA_TYPE_OVERRIDES[table.upper()]:
                        data_type = SCHEMA_TYPE_OVERRIDES[table.upper()][column_name.upper()]

                columns.append((column_name, data_type))

            schema_details[table] = columns

        # Return the full schema details without filtering.
        return schema_details
    except Exception as e:
        return {"error": str(e)}
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def get_user_departments(user_email: str) -> List[str]:
    """
    Retrieves the user's departments from Snowflake based on their email.
    """
    dept_query = """SELECT "dept" FROM "USERROLE" WHERE "empname" = %s"""
    dept_result = _query_snowflake(dept_query, params=(user_email,))

    if dept_result and "error" not in dept_result[0]:
        dept_str = dept_result[0]["dept"]
        return [dept.strip().lower() for dept in dept_str.split(",")]
    return []


# ------------------ Sample Questions ------------------ #

# Map each department to its list of sample questions.
department_sample_questions = {
    "prod": [
        "Fetch all details of home depot where goods are invoiced",
        "Fetch all details of home depot for open order"
    ],
    "misc": [
        "items",
        "items report"
    ],
    "general": [
        "vendor details"
    ],
    "finance": [
        "Paid Invoice Summary"
    ],
    "aging": [
        "aging details",
        "Vendor Summary",
    ],
    "purchase": [
        "show purhcase requisition or show PR or all PR or all purchase requisition"
    ]
}


def get_table_sample_questions(table_name: str, user_email: str) -> List[str]:
    """
    Returns sample questions specific to a table.
    You can customize this with table-specific questions.
    """
    # Add table-specific questions (expand this dictionary as needed)
    table_questions = {
        "USERROLE": [
            "Show me all user roles",
            "Which departments do users belong to?"
        ],
        "ROLE": [
            "What table access does each department have?",
            "Show me role details"
        ],
        # Add more table-specific questions here
    }

    # Combine default questions with any table-specific ones
    if table_name.upper() in table_questions:
        return table_questions[table_name.upper()]
    # return default_questions





