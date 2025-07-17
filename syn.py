# enhanced_synonym_correction.py
import re
from typing import Dict, List, Tuple
import pandas as pd
import json


def get_synonym_mappings(engine) -> pd.DataFrame:
    """Fetch all synonym mappings from Snowflake."""
    query = """
    SELECT table_name, column_name, synonym 
    FROM SYNONYM_MAPPINGS
    """
    with engine.connect() as conn:
        return pd.read_sql(query, conn)


def identify_relevant_tables(user_question: str, schema_text: str, conversation_history: List[Dict],
                             groq_response_func) -> List[str]:
    """Use LLM to identify which tables can answer the user's question."""

    # Include conversation history for context
    history_text = ""
    if conversation_history:
        history_text = "Previous conversation:\n"
        for msg in conversation_history[-6:]:  # Last 3 exchanges
            history_text += f"{msg['role'].upper()}: {msg['content']}\n"
        history_text += "\n"

    prompt = f"""
    Given the user's question, conversation history, and the database schema, identify which table(s) are most likely needed to answer this question.

    {history_text}
    Current User Question: {user_question}

    Database Schema:
    {schema_text}

    Instructions:
    1. Analyze the question to understand what information is being requested
    2. Consider the conversation context - if this is a follow-up question, use the same tables as the previous queries
    3. Look at the available tables and their columns
    4. Return ONLY the table names that are relevant to answering this question
    5. Return the response as a JSON array of table names
    6. If multiple tables might be relevant, include all of them
    7. BE VERY SPECIFIC - only include tables that directly contain the data needed

    Example: 
    - For "How many purchase requisitions were created?", return ["PURCHASE_REQUISITION"]
    - For "How many POs in company X?", return ["PO_DETAILS"]

    Response:
    """

    messages = [
        {"role": "system",
         "content": "You are a database expert that identifies relevant tables for SQL queries. Be precise and only select tables that directly answer the question."},
        {"role": "user", "content": prompt}]

    response, _ = groq_response_func(messages)

    try:
        # Parse the JSON response
        tables = json.loads(response.strip())
        if isinstance(tables, list):
            return [table.upper() for table in tables]
    except:
        # Fallback: extract table names using regex
        tables = re.findall(r'["\']?([A-Za-z_]+)["\']?', response)
        return [table.upper() for table in tables if table.upper() in schema_text.upper()]

    return []


def find_and_replace_synonyms_strict(user_question: str, relevant_tables: List[str],
                                     synonym_mappings: pd.DataFrame, conversation_history: List[Dict],
                                     groq_response_func) -> Tuple[str, Dict[str, str]]:
    """
    Find synonyms in the question and replace them ONLY if they belong to the identified tables.
    This is the STRICT version that ensures table-specific synonym application.
    """

    # Filter synonym mappings for ONLY the relevant tables
    relevant_mappings = synonym_mappings[
        synonym_mappings['table_name'].str.upper().isin([t.upper() for t in relevant_tables])]

    if relevant_mappings.empty:
        return user_question, {}

    # Create a mapping dictionary grouped by table
    synonym_dict = {}
    for _, row in relevant_mappings.iterrows():
        table = row['table_name'].upper()
        if table not in synonym_dict:
            synonym_dict[table] = []
        synonym_dict[table].append({
            'synonym': row['synonym'],
            'column_name': row['column_name']
        })

    # Include conversation history
    history_text = ""
    if conversation_history:
        history_text = "Previous conversation (with any corrections already applied):\n"
        for msg in conversation_history[-6:]:
            history_text += f"{msg['role'].upper()}: {msg['content']}\n"
        history_text += "\n"

    prompt = f"""
    Given a user question and synonym mappings, identify which synonyms appear in the question and suggest replacements.

    CRITICAL RULES:
    1. ONLY apply synonyms if they are defined for the tables that will answer this question
    2. The relevant tables for this question are: {relevant_tables}
    3. DO NOT apply synonyms from other tables even if the same word appears
    4. Be very strict - if unsure, do not replace

    {history_text}
    Current User Question: {user_question}

    Synonym Mappings for the RELEVANT TABLES ONLY:
    {json.dumps(synonym_dict, indent=2)}

    Instructions:
    1. Look for terms in the question that match synonyms in the provided mappings
    2. ONLY replace if the synonym belongs to one of the relevant tables: {relevant_tables}
    3. If a term appears as a synonym in multiple tables, ONLY use it if one of those tables is in the relevant list
    4. Return a JSON object with the corrected question and replacements

    Example:
    - Question: "How many purchase requisitions in data area 001?"
    - Relevant tables: ["PURCHASE_REQUISITION"]  
    - If "data area" -> "company" mapping exists only for PO_DETAILS table, DO NOT replace it
    - Return the original question unchanged

    Response format:
    {{
        "corrected_question": "the question with synonyms replaced (or unchanged if no valid replacements)",
        "replacements": {{
            "original_term": "replacement_term"
        }},
        "reasoning": "brief explanation of why replacements were or weren't made"
    }}

    Response:
    """

    messages = [
        {"role": "system",
         "content": "You are a database expert that applies synonym corrections STRICTLY based on table context. Never apply synonyms from unrelated tables."},
        {"role": "user", "content": prompt}
    ]

    response, _ = groq_response_func(messages)

    try:
        result = json.loads(response.strip())
        return result.get('corrected_question', user_question), result.get('replacements', {})
    except:
        # Fallback: manual synonym replacement with strict table checking
        corrected_question = user_question
        replacements = {}

        # Only process mappings for the specific relevant tables
        for _, row in relevant_mappings.iterrows():
            if row['table_name'].upper() in [t.upper() for t in relevant_tables]:
                synonym = row['synonym'].lower()
                column_name = row['column_name'].lower()

                # Case-insensitive replacement
                pattern = re.compile(r'\b' + re.escape(synonym) + r'\b', re.IGNORECASE)
                if pattern.search(corrected_question):
                    corrected_question = pattern.sub(column_name, corrected_question)
                    replacements[synonym] = column_name

        return corrected_question, replacements


def correct_user_question(user_question: str, schema_text: str, engine, groq_response_func,
                          conversation_history: List[Dict] = None) -> Tuple[str, Dict]:
    """Main function to correct user questions using synonym mappings with STRICT table checking."""

    if conversation_history is None:
        conversation_history = []

    # Step 1: Get synonym mappings from Snowflake
    try:
        synonym_mappings = get_synonym_mappings(engine)
    except Exception as e:
        print(f"Error fetching synonym mappings: {e}")
        return user_question, {"error": "Could not fetch synonym mappings"}

    if synonym_mappings.empty:
        return user_question, {"message": "No synonym mappings found"}

    # Step 2: Identify relevant tables for the question
    relevant_tables = identify_relevant_tables(user_question, schema_text, conversation_history, groq_response_func)

    if not relevant_tables:
        return user_question, {"message": "Could not identify relevant tables"}

    # Step 3: Find and replace synonyms with STRICT table checking
    corrected_question, replacements = find_and_replace_synonyms_strict(
        user_question, relevant_tables, synonym_mappings, conversation_history, groq_response_func
    )

    # Only return as corrected if actual replacements were made
    if not replacements:
        return user_question, {
            "original_question": user_question,
            "corrected_question": user_question,
            "relevant_tables": relevant_tables,
            "replacements": {},
            "message": "No applicable synonyms found for the identified tables"
        }

    return corrected_question, {
        "original_question": user_question,
        "corrected_question": corrected_question,
        "relevant_tables": relevant_tables,
        "replacements": replacements
    }


def get_contextual_rules(engine) -> pd.DataFrame:
    """Fetch all active contextual replacement rules from Snowflake."""
    query = """
    SELECT rule_id, required_keywords, excluded_keywords, target_word, 
           replacement, priority, rule_description
    FROM CONTEXTUAL_REPLACEMENT_RULES
    WHERE is_active = TRUE
    ORDER BY priority ASC
    """
    with engine.connect() as conn:
        return pd.read_sql(query, conn)


def apply_contextual_rules_from_table(question: str, engine, groq_response_func) -> Tuple[str, Dict[str, str]]:
    """Apply context-based replacements using rules from the database table."""

    # Fetch rules from db
    try:
        rules_df = get_contextual_rules(engine)
    except Exception as e:
        print(f"Error fetching contextual rules: {e}")
        return question, {}

    if rules_df.empty:
        return question, {}

    # Convert rules to a format for the LLM
    rules_list = []
    for _, rule in rules_df.iterrows():
        rule_dict = {
            "rule_id": int(rule['rule_id']),
            "required_keywords": rule['required_keywords'].split(',') if pd.notna(rule['required_keywords']) else [],
            "excluded_keywords": rule['excluded_keywords'].split(',') if pd.notna(rule['excluded_keywords']) else [],
            "target_word": rule['target_word'],
            "replacement": rule['replacement'],
            "description": rule['rule_description']
        }
        rules_list.append(rule_dict)

    prompt = f"""
    Apply contextual replacement rules to the following question. Process rules in order of priority.

    Question: {question}

    Rules to apply:
    {json.dumps(rules_list, indent=2)}

    Instructions:
    1. For each rule, check if the target_word exists in the question (case-insensitive)
    2. If target_word exists:
       - If required_keywords is not empty: Check if ANY of the required keywords are present
       - If excluded_keywords is not empty: Check that NONE of the excluded keywords are present
    3. Apply the replacement if conditions are met
    4. Process rules in order - once a word is replaced by a rule, don't apply other rules to it
    5. Return the corrected question and what replacements were made

    Response format:
    {{
        "corrected_question": "the question with contextual replacements",
        "replacements": {{
            "original_term": "replacement_term"
        }},
        "rules_applied": ["rule_id_1", "rule_id_2"]
    }}

    Response:
    """

    messages = [
        {"role": "system",
         "content": "You are an expert at applying contextual replacement rules to database queries."},
        {"role": "user", "content": prompt}
    ]

    try:
        response, _ = groq_response_func(messages)
        result = json.loads(response.strip())
        return result.get('corrected_question', question), result.get('replacements', {})
    except:
        # Fallback: manual rule application
        corrected_question = question
        replacements = {}
        question_lower = question.lower()

        for _, rule in rules_df.iterrows():
            target_word = rule['target_word'].lower()

            # Check if target word exists in question
            if target_word in question_lower:
                apply_rule = True

                # Check required keywords (ANY must be present)
                if pd.notna(rule['required_keywords']):
                    required = [kw.strip().lower() for kw in rule['required_keywords'].split(',')]
                    apply_rule = any(kw in question_lower for kw in required)

                # Check excluded keywords (NONE must be present)
                if apply_rule and pd.notna(rule['excluded_keywords']):
                    excluded = [kw.strip().lower() for kw in rule['excluded_keywords'].split(',')]
                    apply_rule = not any(kw in question_lower for kw in excluded)

                # Apply replacement if conditions are met
                if apply_rule:
                    pattern = re.compile(r'\b' + re.escape(rule['target_word']) + r'\b', re.IGNORECASE)
                    corrected_question = pattern.sub(rule['replacement'], corrected_question)
                    replacements[rule['target_word']] = rule['replacement']
                    # Update question_lower for subsequent iterations
                    question_lower = corrected_question.lower()

        return corrected_question, replacements


def correct_user_question_enhanced(user_question: str, schema_text: str, engine, groq_response_func,
                                   conversation_history: List[Dict] = None) -> Tuple[str, Dict]:
    """Enhanced version that applies both contextual rules and synonym corrections with STRICT table checking."""

    if conversation_history is None:
        conversation_history = []

    # Step 1: Apply contextual replacements from table
    contextual_corrected, contextual_replacements = apply_contextual_rules_from_table(
        user_question, engine, groq_response_func
    )

    # Step 2: Apply synonym corrections on the contextually corrected question
    final_corrected, synonym_info = correct_user_question(
        contextual_corrected,  # Use the contextually corrected version
        schema_text,
        engine,
        groq_response_func,
        conversation_history
    )

    # Combine all replacements
    all_replacements = {}
    if contextual_replacements:
        all_replacements.update(contextual_replacements)
    if synonym_info.get('replacements'):
        all_replacements.update(synonym_info.get('replacements'))

    # Return combined results
    return final_corrected, {
        "original_question": user_question,
        "corrected_question": final_corrected,
        "relevant_tables": synonym_info.get('relevant_tables', []),
        "replacements": all_replacements,
        "contextual_replacements": contextual_replacements,
        "synonym_replacements": synonym_info.get('replacements', {})
    }