# ui_based_error_recovery.py

import re
from typing import Dict, List
import streamlit as st
from sqlalchemy import text  # ADD THIS IMPORT


def extract_all_filters_from_sql(sql_query: str) -> Dict[str, List[Dict]]:
    """
    Extract ALL filter conditions from SQL query including table info
    Returns dict with filters and table information
    """
    # Extract table name
    table_match = re.search(r'FROM\s+(\w+)', sql_query, re.IGNORECASE)
    table_name = table_match.group(1) if table_match else "Unknown"

    # Extract WHERE clause
    where_match = re.search(r'WHERE\s+(.*?)(?:GROUP\s+BY|ORDER\s+BY|LIMIT|$)', sql_query, re.IGNORECASE | re.DOTALL)
    if not where_match:
        return {"table": table_name, "filters": []}

    where_clause = where_match.group(1)
    filters = []

    # Patterns to match different types of conditions
    patterns = [
        # String comparisons with LIKE/ILIKE
        (r"(\w+)\s+(ILIKE|LIKE)\s*'%?([^%']+)%?'", "string"),
        (r"(\w+)\s+(ILIKE|LIKE)\s*\"%?([^%\"]+)%?\"", "string"),
        # String equality
        (r"(\w+)\s*=\s*'([^']+)'", "string"),
        (r"(\w+)\s*=\s*\"([^\"]+)\"", "string"),
        # Numeric comparisons
        (r"(\w+)\s*(=|!=|<>|<=|>=|<|>)\s*(\d+(?:\.\d+)?)", "numeric"),
        # IN clause
        (r"(\w+)\s+IN\s*\(([^)]+)\)", "in_clause"),
    ]

    # Track which parts of WHERE clause we've already processed
    processed_positions = []

    for pattern, filter_type in patterns:
        for match in re.finditer(pattern, where_clause, re.IGNORECASE):
            # Check if this match overlaps with already processed parts
            start, end = match.span()
            if any(start < p_end and end > p_start for p_start, p_end in processed_positions):
                continue

            processed_positions.append((start, end))

            if filter_type == "in_clause":
                column = match.group(1)
                values = match.group(2).strip()
                # Extract individual values from IN clause
                value_list = re.findall(r"'([^']+)'|\"([^\"]+)\"|(\d+)", values)
                cleaned_values = [v for sublist in value_list for v in sublist if v]
                filters.append({
                    "column": column,
                    "operator": "IN",
                    "value": ", ".join(cleaned_values),
                    "type": "string" if any(re.match(r"'|\"", values)) else "numeric"
                })
            else:
                if len(match.groups()) == 3:
                    column, operator, value = match.groups()
                else:
                    column, value = match.groups()
                    operator = "="

                # Skip EXTRACT functions and other function calls
                if "EXTRACT(" in where_clause[max(0, start - 10):start]:
                    continue

                filters.append({
                    "column": column,
                    "operator": operator,
                    "value": value.strip("'\""),
                    "type": filter_type
                })

    return {
        "table": table_name,
        "filters": filters
    }


def generate_ui_clarification_message(filter_info: Dict, result_type: str) -> str:
    """
    Generate the clarification message with placeholders for input boxes
    """
    message = """I couldn't find any results for your query.

I searched with the following:

"""

    # List all filters
    for i, filter_item in enumerate(filter_info["filters"], 1):
        message += f"{i}. **{filter_item['value']}** in column **{filter_item['column']}**\n"

    # Add table info
    message += f"\nTable used: **{filter_info['table']}**\n\n"

    message += """To help me find the correct data, please tell me what each value represents. For example:
- "2500148150 is a project ID"
- "Elite Disaster Team is a vendor name"
- "Use AP_DETAILS table instead"

Or type **"correct"** if everything looks right."""

    return message


def render_correction_ui(filter_info: Dict, message_key: str) -> Dict[str, str]:
    """
    Render the UI with input boxes for corrections
    Returns a dictionary of corrections entered by the user
    """
    corrections = {}

    # Create numbered list with input boxes for each filter
    for i, filter_item in enumerate(filter_info["filters"], 1):
        col1, col2 = st.columns([1, 2])

        with col1:
            st.markdown(f"{i}. **{filter_item['value']}**")

        with col2:
            # Use a hidden label to avoid warnings
            correction = st.text_input(
                label=f"Correction for {filter_item['value']}",
                key=f"{message_key}_filter_{i}",
                placeholder="Leave empty if correct",
                label_visibility="collapsed"
            )
            if correction:
                corrections[f"{filter_item['column']}:{filter_item['value']}"] = correction

    # Table correction
    st.markdown(f"**{len(filter_info['filters']) + 1}. {filter_info['table']}**")
    table_correction = st.text_input(
        label=f"Table correction",
        key=f"{message_key}_table",
        placeholder="Leave empty if correct",
        label_visibility="collapsed"
    )
    if table_correction:
        corrections["table"] = table_correction

    # Note at the bottom
    st.markdown(
        "**NOTE:** Leave the box empty for the corresponding thing if you feel everything is correct with that particular case")

    return corrections


def handle_ui_based_error_recovery(
        sql_query: str,
        result: any,
        error_message: str,
        schema_text: str,
        groq_response_func,
        user_email: str
) -> Dict:
    """
    Enhanced error recovery with UI-based corrections
    """
    # Check if we need error recovery
    needs_recovery = False
    result_type = None

    if isinstance(result, dict) and "error" in result:
        needs_recovery = True
        error_message = result.get("error", "")
        result_type = "error"
    elif isinstance(result, list) and len(result) == 0:
        needs_recovery = True
        result_type = "empty"
    elif isinstance(result, list) and len(result) == 1:
        # Check for null/zero values
        row = result[0]
        if all(value is None for value in row.values()):
            needs_recovery = True
            result_type = "null"
        elif all(value == 0 or value is None for value in row.values()):
            needs_recovery = True
            result_type = "zero"

    if not needs_recovery:
        return {"needs_clarification": False}

    # Extract all filters
    filter_info = extract_all_filters_from_sql(sql_query)

    # If no filters found, can't do correction
    if not filter_info["filters"]:
        return {"needs_clarification": False}

    # Generate clarification message
    message = generate_ui_clarification_message(filter_info, result_type)

    return {
        "needs_clarification": True,
        "message": message,
        "filter_info": filter_info,
        "original_sql": sql_query,
        "ui_type": "streamlit"
    }


def save_clarification_to_instructions(corrections: Dict[str, str], snowflake_engine) -> None:
    """
    Save user clarifications to INSTRUCTIONS_NEW table
    """
    try:
        instructions_to_save = []

        for key, description in corrections.items():
            if key == "table":
                # Skip table corrections for now, or handle differently if needed
                continue
            else:
                # Extract the value from the key (format: "column:value")
                if ":" in key:
                    _, value = key.split(":", 1)
                    # Create instruction in the format: "Elite Disaster Team : it is a vendors name"
                    instruction = f"{value} : {description}"
                    instructions_to_save.append(instruction)

        # Save each instruction to the database
        if instructions_to_save and snowflake_engine:
            with snowflake_engine.connect() as conn:
                for instruction in instructions_to_save:
                    # Insert into INSTRUCTIONS_NEW table
                    insert_query = text("""
                        INSERT INTO ATI_AI_USAGE.INSTRUCTIONS_NEW ("INSTRUCTION", "DELETED")
                        VALUES (:instruction, FALSE)
                    """)
                    conn.execute(insert_query, {"instruction": instruction})
                    conn.commit()
                    print(f"✅ Saved instruction: {instruction}")

    except Exception as e:
        print(f"❌ Error saving clarification to instructions: {e}")
        # Don't fail the whole process if saving fails


def process_ui_corrections(
        corrections: Dict[str, str],
        filter_info: Dict,
        original_sql: str,
        schema_text: str,
        groq_response_func,
        snowflake_engine=None,  # ADD THIS PARAMETER
        user_email=None,  # ADD THIS PARAMETER (kept for compatibility)
        original_question=None  # ADD THIS PARAMETER (kept for compatibility)
) -> Dict:
    """
    Process UI corrections and generate fixed SQL
    NOW SAVES TO INSTRUCTIONS_NEW TABLE
    """
    if not corrections:
        return {
            "needs_retry": False,
            "message": "No corrections provided. The query result stands as is."
        }

    # Build correction instructions
    correction_instructions = []

    for key, description in corrections.items():
        if key == "table":
            correction_instructions.append(f"- The table should be {description}")
        else:
            column, value = key.split(":", 1)
            correction_instructions.append(f"- '{value}' is a {description}, currently in column {column}")

    prompt = f"""Fix this SQL query based on the user's corrections.

Original SQL:
{original_sql}

Database Schema:
{schema_text}

User Corrections:
{chr(10).join(correction_instructions)}

Instructions:
1. Find the correct column names based on the user's descriptions
2. Update the table name if requested
3. Keep the same query structure and logic
4. Return ONLY the corrected SQL query, no explanation

Corrected SQL:"""

    response, _ = groq_response_func([{"role": "user", "content": prompt}])

    # Clean the response
    fixed_sql = response.strip()
    if fixed_sql.startswith("```sql"):
        fixed_sql = fixed_sql[6:]
    if fixed_sql.startswith("```"):
        fixed_sql = fixed_sql[3:]
    if fixed_sql.endswith("```"):
        fixed_sql = fixed_sql[:-3]

    # ==== SAVE TO INSTRUCTIONS_NEW TABLE ====
    if snowflake_engine:
        save_clarification_to_instructions(corrections, snowflake_engine)
    # ==== END SAVE ====

    # Build summary of changes
    changes_summary = []
    for key, desc in corrections.items():
        if key == "table":
            changes_summary.append(f"Changed table to {desc}")
        else:
            col, val = key.split(":", 1)
            changes_summary.append(f"'{val}' → searching as {desc}")

    return {
        "needs_retry": True,
        "fixed_sql": fixed_sql.strip(),
        "message": f"I'll apply these corrections:\n" + "\n".join(f"• {c}" for c in changes_summary),
        "corrections_applied": corrections
    }
