# continuation_detection.py
import re
import json
from typing import Dict, List, Tuple, Optional


def extract_table_from_query(sql_query: str) -> List[str]:
    """Extract table names from SQL query."""
    # Remove newlines and extra spaces
    sql_query = ' '.join(sql_query.split())

    # Common patterns to find table names
    patterns = [
        r'FROM\s+(\w+)',
        r'JOIN\s+(\w+)',
        r'INTO\s+(\w+)',
        r'UPDATE\s+(\w+)',
        r'TABLE\s+(\w+)'
    ]

    tables = []
    for pattern in patterns:
        matches = re.findall(pattern, sql_query, re.IGNORECASE)
        tables.extend(matches)

    # Remove duplicates and return
    return list(set(tables))


def combine_questions_with_llm(current_question: str, previous_question: str, groq_response_func) -> str:
    """
    Use LLM to combine current and previous questions into a meaningful single question.
    """
    combination_prompt = f"""
    You need to enhance the current question using context from the previous question to make it complete and meaningful.

    Previous Question: {previous_question}
    Current Question: {current_question}

    The current question is a follow-up that lacks context. Use information from the previous question to make the current question self-contained and meaningful.

    IMPORTANT: 
    - DO NOT try to answer both questions
    - Focus on answering the CURRENT question only
    - Use context from previous question to fill in missing details in current question
    - Make the current question complete so it doesn't need additional context

    Examples:
    - Previous: "no of pos created"
    - Current: "in the last year"
    - Combined: "What is the number of POs created in the last year?"

    - Previous: "show me sales data for Q1 2023"
    - Current: "which month had highest sales"
    - Enhanced: "Which month in Q1 2023 had the highest sales?"

    - Previous: "what are the employees in marketing department"
    - Current: "who has the highest salary"
    - Enhanced: "Who has the highest salary in the marketing department?"

    Respond with only the enhanced question, nothing else.
    """

    messages = [
        {"role": "system", "content": "You are an expert at combining related questions into coherent, meaningful queries."},
        {"role": "user", "content": combination_prompt}
    ]

    try:
        response, _ = groq_response_func(messages)
        # Clean the response and return
        combined_question = response.strip().strip('"').strip("'")
        return combined_question
    except Exception as e:
        # Fallback to simple combination if LLM fails
        return f"{current_question} (from the context of: {previous_question})"


def detect_continuation_question(
        current_question: str,
        previous_question: str,
        previous_sql: str,
        current_sql: str,
        schema_text: str,
        groq_response_func
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Detect if current question is a continuation of previous question.
    Returns: (is_continuation, suggested_combined_question, explanation)
    """

    # Extract tables from both queries
    prev_tables = extract_table_from_query(previous_sql)
    curr_tables = extract_table_from_query(current_sql)

    # If they don't use the same table, it's not a continuation
    if not prev_tables or not curr_tables:
        return False, None, None

    # Check if there's table overlap
    common_tables = set(prev_tables) & set(curr_tables)
    if not common_tables:
        return False, None, None

    # Use LLM to analyze if this is a continuation
    analysis_prompt = f"""
    Analyze if Question 2 is a continuation or follow-up of Question 1.

    Question 1: {previous_question}
    SQL 1: {previous_sql}

    Question 2: {current_question}
    SQL 2: {current_sql}

    Common tables used: {', '.join(common_tables)}

    Rules for continuation detection:
    1. Both questions must use the same table(s)
    2. Question 2 should be asking for additional details or filtering of Question 1's context
    3. Question 2 might use pronouns (it, that, which) or be incomplete without Question 1's context
    4. Question 2 might be asking for a subset, maximum, minimum, or specific detail from Question 1's scope

    Respond in JSON format:
    {{
        "is_continuation": true/false,
        "confidence": "high"/"medium"/"low",
        "reasoning": "brief explanation",
        "combined_question": "suggested combined question if continuation, else null"
    }}
    """

    messages = [
        {"role": "system", "content": "You are an expert at analyzing SQL queries and natural language questions."},
        {"role": "user", "content": analysis_prompt}]

    response, _ = groq_response_func(messages)

    try:
        result = json.loads(response)

        if result.get('is_continuation') and result.get('confidence') in ['high', 'medium']:
            return True, result.get('combined_question'), result.get('reasoning')
    except:
        # Fallback to simple heuristic if LLM fails
        continuation_keywords = ['which', 'what', 'that', 'those', 'maximum', 'minimum', 'most', 'least', 'highest',
                                 'lowest']
        current_lower = current_question.lower()

        # Check for continuation indicators
        has_continuation_word = any(word in current_lower for word in continuation_keywords)
        missing_context = len(current_question.split()) < 8  # Short questions often lack context

        if has_continuation_word and missing_context and common_tables:
            # Use LLM mechanism to combine questions meaningfully
            combined = combine_questions_with_llm(current_question, previous_question, groq_response_func)
            return True, combined, "Question appears to reference previous context"

    return False, None, None


def format_continuation_options(
        original_question: str,
        combined_question: str,
        previous_question: str
) -> str:
    """Format the options for user to choose from."""

    formatted_response = f"""
🔄 **Continuation Question Detected**

I noticed your current question might be related to your previous question about: *"{previous_question}"*

Please select which interpretation you meant:

**1)** {original_question} *(interpret as standalone question)*

**2)** {combined_question} *(interpret as continuation of previous question)*

Type **1** or **2** to select your preferred interpretation, or rephrase your question if neither is correct.
"""

    return formatted_response


def handle_continuation_detection(
        current_question: str,
        chat_history: List[Dict],
        schema_text: str,
        groq_response_func,
        get_last_sql_query_func
) -> Dict:
    """
    Main function to handle continuation detection.
    Returns dict with detection results and formatted response.
    """

    # Find the last user question and its SQL
    previous_user_question = None
    previous_sql = None

    # Get last user message (excluding current)
    for msg in reversed(chat_history[:-1]):  # Exclude current message
        if msg["role"] == "user":
            previous_user_question = msg["content"]
            break

    if not previous_user_question:
        return {
            "is_continuation": False,
            "formatted_response": None,
            "options": None
        }

    # Get the SQL for previous question (you'll need to implement this based on your system)
    previous_sql = get_last_sql_query_func()

    if not previous_sql:
        return {
            "is_continuation": False,
            "formatted_response": None,
            "options": None
        }

    # Generate SQL for current question first
    current_sql_response, _ = groq_response_func(chat_history)
    current_sql = current_sql_response.strip()

    # Clean SQL
    if current_sql.startswith("```sql"):
        current_sql = current_sql[6:]
    if current_sql.startswith("```"):
        current_sql = current_sql[3:]
    if current_sql.endswith("```"):
        current_sql = current_sql[:-3]
    current_sql = current_sql.strip()

    # Detect continuation
    is_continuation, combined_question, reasoning = detect_continuation_question(
        current_question,
        previous_user_question,
        previous_sql,
        current_sql,
        schema_text,
        groq_response_func
    )

    if is_continuation and combined_question:
        formatted_response = format_continuation_options(
            current_question,
            combined_question,
            previous_user_question
        )

        return {
            "is_continuation": True,
            "formatted_response": formatted_response,
            "options": {
                "1": current_question,
                "2": combined_question
            },
            "original_sql": current_sql,
            "reasoning": reasoning
        }

    return {
        "is_continuation": False,
        "formatted_response": None,
        "options": None,
        "original_sql": current_sql
    }


# Integration function for your main.py
def check_and_handle_continuation(
        user_input: str,
        messages: List[Dict],
        schema_text: str,
        groq_response_func,
        last_sql_query: str = None
) -> Dict:
    """
    Integration function to be called from your main application.

    Args:
        user_input: Current user question
        messages: Chat history
        schema_text: Database schema information
        groq_response_func: Your groq response function
        last_sql_query: The SQL query from the previous question

    Returns:
        Dictionary with continuation detection results
    """

    # Create a function to return the last SQL query
    def get_last_sql():
        return last_sql_query

    # Add current question to a copy of messages for analysis
    temp_messages = messages.copy()
    temp_messages.append({"role": "user", "content": user_input})

    result = handle_continuation_detection(
        user_input,
        temp_messages,
        schema_text,
        groq_response_func,
        get_last_sql
    )

    return result