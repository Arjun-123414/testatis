import sqlglot
from fuzzywuzzy import process
import snowflake.connector
import os
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


def extract_query_components(sql_query):
    """
    Extract key components from an SQL query using SQLGlot

    Args:
        sql_query (str): SQL query to parse

    Returns:
        dict: Extracted query components
    """
    try:
        # Parse the SQL query
        parsed = sqlglot.parse_one(sql_query)

        # Extract table name
        table_node = parsed.find(sqlglot.exp.Table)
        table_name = table_node.name.replace('"', '') if table_node else None

        # Extract column and value conditions
        conditions = []
        for condition in parsed.find_all(sqlglot.exp.EQ):
            try:
                # Extract column name
                column = condition.left.name.replace('"', '')

                # Handle different types of literal values
                right_value = condition.right
                if isinstance(right_value, sqlglot.exp.Literal):
                    value = str(right_value.this).strip("'")
                elif hasattr(right_value, 'value'):
                    value = str(right_value.value).strip("'")
                else:
                    value = str(right_value).strip("'")

                conditions.append({
                    'column': column,
                    'value': value
                })
            except Exception as inner_e:
                print(f"Error processing individual condition: {inner_e}")

        return {
            'table_name': table_name,
            'conditions': conditions
        }
    except Exception as e:
        print(f"Error extracting query components: {e}")
        return None


def get_similar_entries(table_name, column_name, incorrect_value, conn):
    """
    Find similar entries in the specified table and column

    Args:
        table_name (str): Name of the table to search
        column_name (str): Name of the column to search
        incorrect_value (str): Incorrect value to find matches for
        conn (snowflake.connector.connection): Snowflake connection

    Returns:
        list: List of similar entries
    """
    try:
        # Ensure table and column names are properly quoted
        quoted_table = f'"{table_name}"'
        quoted_column = f'"{column_name}"'

        # Query to get unique values from the specified column
        query = f'SELECT DISTINCT {quoted_column} FROM {quoted_table}'
        cursor = conn.cursor()
        cursor.execute(query)

        # Fetch all unique values
        unique_values = [str(row[0]).strip() for row in cursor.fetchall() if row[0] is not None]

        # Use fuzzy matching to find close matches
        matches = process.extractBests(str(incorrect_value).strip(), unique_values, limit=5, score_cutoff=70)

        return [match[0] for match in matches]
    except Exception as e:
        print(f"Error finding similar entries: {e}")
        return []


def suggest_query_correction(sql_query, user_email):
    """
    Suggest query corrections when no results are found

    Args:
        sql_query (str): Original SQL query
        user_email (str): User's email for connection

    Returns:
        dict: Suggestions for query correction
    """
    try:
        # Extract query components
        query_components = extract_query_components(sql_query)
        if not query_components or not query_components['table_name']:
            return None

        # Establish Snowflake connection
        conn = snowflake.connector.connect(
            user=os.getenv("SNOWFLAKE_USER"),
            account=os.getenv("SNOWFLAKE_ACCOUNT"),
            private_key=get_private_key(),
            warehouse="PROD_QUERY_WH",
            database="ATI_PROD_V1",
            schema="AGENTAI",
        )

        # Collect suggestions for each condition
        suggestions = []
        for condition in query_components['conditions']:
            similar_entries = get_similar_entries(
                query_components['table_name'],
                condition['column'],
                condition['value'],
                conn
            )

            if similar_entries:
                suggestions.append({
                    'column': condition['column'],
                    'original_value': condition['value'],
                    'suggested_values': similar_entries
                })

        conn.close()

        return {
            'table_name': query_components['table_name'],
            'suggestions': suggestions
        } if suggestions else None

    except Exception as e:
        print(f"Error in query correction: {e}")
        return None


def enhance_query_correction(sql_query, extract_func=extract_query_components):
    """
    Enhanced query correction mechanism supporting multiple matching strategies

    Args:
        sql_query (str): Original SQL query
        extract_func (callable): Function to extract query components

    Returns:
        dict: Refined correction suggestions
    """
    try:
        # Extract query components
        query_components = extract_func(sql_query)
        if not query_components or not query_components['table_name']:
            return None

        # Establish Snowflake connection
        conn = snowflake.connector.connect(
            user=os.getenv("SNOWFLAKE_USER"),
            account=os.getenv("SNOWFLAKE_ACCOUNT"),
            private_key=get_private_key(),
            warehouse="PROD_QUERY_WH",
            database="ATI_PROD_V1",
            schema="AGENTAI",
        )

        # Collect suggestions for each condition
        suggestions = []
        for condition in query_components['conditions']:
            # Multiple matching strategies
            correction_strategies = [
                # Exact match (current implementation)
                lambda val: get_similar_entries(
                    query_components['table_name'],
                    condition['column'],
                    val,
                    conn
                ),
                # Case-insensitive match
                lambda val: get_similar_entries_ilike(
                    query_components['table_name'],
                    condition['column'],
                    val,
                    conn
                )
            ]

            # Collect unique suggestions across strategies
            unique_suggestions = set()
            for strategy in correction_strategies:
                similar_entries = strategy(condition['value'])
                unique_suggestions.update(similar_entries)

            # Remove exact match to avoid redundancy
            unique_suggestions = {
                entry for entry in unique_suggestions
                if entry.lower() != condition['value'].lower()
            }

            if unique_suggestions:
                suggestions.append({
                    'column': condition['column'],
                    'original_value': condition['value'],
                    'suggested_values': list(unique_suggestions)
                })

        conn.close()

        return {
            'table_name': query_components['table_name'],
            'suggestions': suggestions
        } if suggestions else None

    except Exception as e:
        print(f"Error in enhanced query correction: {e}")
        return None


def get_similar_entries_ilike(table_name, column_name, incorrect_value, conn):
    """
    Find similar entries using case-insensitive ILIKE matching

    Args:
        table_name (str): Name of the table to search
        column_name (str): Name of the column to search
        incorrect_value (str): Incorrect value to find matches for
        conn (snowflake.connector.connection): Snowflake connection

    Returns:
        list: List of similar entries
    """
    try:
        # Ensure table and column names are properly quoted
        quoted_table = f'"{table_name}"'
        quoted_column = f'"{column_name}"'

        # Use ILIKE for case-insensitive partial matching
        query = f'''
        SELECT DISTINCT {quoted_column} 
        FROM {quoted_table} 
        WHERE {quoted_column} ILIKE '%{incorrect_value}%' 
        OR {quoted_column} IS NOT DISTINCT FROM %s
        LIMIT 5
        '''

        cursor = conn.cursor()
        cursor.execute(query, (incorrect_value,))

        # Fetch matching values
        unique_values = [str(row[0]).strip() for row in cursor.fetchall() if row[0] is not None]

        # Use fuzzy matching as a secondary filter
        matches = process.extractBests(
            str(incorrect_value).strip(),
            unique_values,
            limit=5,
            score_cutoff=60
        )

        return [match[0] for match in matches]
    except Exception as e:
        print(f"Error finding similar entries (ILIKE): {e}")
        return []


def format_professional_suggestion(correction_suggestions):
    """
    Create a professional, conversational suggestion message

    Args:
        correction_suggestions (dict): Query correction suggestions

    Returns:
        str: Formatted, user-friendly suggestion
    """
    if not correction_suggestions or not correction_suggestions.get('suggestions'):
        return None

    # Start with an empty suggestion message
    suggestion_message = ""

    # Process each suggestion
    for suggestion in correction_suggestions['suggestions']:
        # Extract column and original value
        column = suggestion['column']
        original_value = suggestion['original_value']

        # Create suggestion for this specific column
        suggestion_message += f"It looks like '**{original_value}**' in your query might be a typo. Here are some possible matches I found in the database:\n\n"


        # Numbered list of suggestions
        for i, value in enumerate(suggestion['suggested_values'], 1):
            suggestion_message += f"{i}. {value}\n"

        suggestion_message += "\n**Please confirm the correct option by typing the exact name from the list i provided.**\n\n"

    return suggestion_message