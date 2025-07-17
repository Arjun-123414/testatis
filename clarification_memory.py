import re
from typing import Dict, List, Tuple
from sqlalchemy import  text
import pandas as pd



class ClarificationMemory:
    """
    A learning system that remembers user clarifications and applies them to future queries.
    This helps avoid asking users for the same clarifications repeatedly.
    """

    def __init__(self, snowflake_engine):
        self.engine = snowflake_engine
        self._ensure_table_exists()

    def _ensure_table_exists(self):
        """Ensure the clarification table exists in Snowflake"""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS QUERY_CLARIFICATIONS (
            id INTEGER AUTOINCREMENT PRIMARY KEY,
            user_email VARCHAR(255),
            original_question VARCHAR(2000),
            original_sql TEXT,
            clarification_type VARCHAR(100),
            clarification_key VARCHAR(500),
            clarification_value VARCHAR(500),
            corrected_column VARCHAR(255),
            corrected_sql TEXT,
            success_flag BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP(),
            last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
        )
        """
        with self.engine.connect() as conn:
            conn.execute(text(create_table_sql))
            conn.commit()

    def save_clarification(self,
                           user_email: str,
                           original_question: str,
                           original_sql: str,
                           corrections: Dict[str, str],
                           corrected_sql: str,
                           filter_info: Dict) -> None:
        """
        Save a clarification to the database for future learning.

        Args:
            user_email: User who made the clarification
            original_question: The original user question
            original_sql: The SQL that produced no results
            corrections: Dict of corrections made by user
            corrected_sql: The SQL after corrections
            filter_info: Information about the filters that were problematic
        """
        try:
            # Process each correction
            for key, value in corrections.items():
                if key == "table":
                    # Table correction
                    self._save_single_clarification(
                        user_email=user_email,
                        original_question=original_question,
                        original_sql=original_sql,
                        clarification_type="table_correction",
                        clarification_key=filter_info.get("table", ""),
                        clarification_value=value,
                        corrected_column="",
                        corrected_sql=corrected_sql
                    )
                else:
                    # Column/value correction
                    # Parse the key format "column:value"
                    if ":" in key:
                        column, original_value = key.split(":", 1)

                        # Find the corrected column from the corrected SQL
                        corrected_column = self._extract_corrected_column(
                            original_sql, corrected_sql, original_value, value
                        )

                        self._save_single_clarification(
                            user_email=user_email,
                            original_question=original_question,
                            original_sql=original_sql,
                            clarification_type="column_mapping",
                            clarification_key=original_value,
                            clarification_value=value,
                            corrected_column=corrected_column,
                            corrected_sql=corrected_sql
                        )

        except Exception as e:
            print(f"Error saving clarification: {e}")

    def _save_single_clarification(self, **kwargs):
        """Save a single clarification record"""
        insert_sql = """
        INSERT INTO QUERY_CLARIFICATIONS (
            user_email, original_question, original_sql, clarification_type,
            clarification_key, clarification_value, corrected_column, corrected_sql
        ) VALUES (
            :user_email, :original_question, :original_sql, :clarification_type,
            :clarification_key, :clarification_value, :corrected_column, :corrected_sql
        )
        """
        with self.engine.connect() as conn:
            conn.execute(text(insert_sql), kwargs)
            conn.commit()

    def _extract_corrected_column(self, original_sql: str, corrected_sql: str,
                                  original_value: str, clarification: str) -> str:
        """Extract the column that was corrected based on SQL comparison"""
        # Find which column changed between original and corrected SQL
        # This is a simplified version - you might need more sophisticated parsing

        # Look for column changes in WHERE clause
        original_where = re.search(r'WHERE(.+?)(?:GROUP|ORDER|LIMIT|$)', original_sql, re.IGNORECASE)
        corrected_where = re.search(r'WHERE(.+?)(?:GROUP|ORDER|LIMIT|$)', corrected_sql, re.IGNORECASE)

        if original_where and corrected_where:
            # Find columns that appear in corrected but not in original
            corrected_columns = re.findall(r'(\w+)\s*(?:=|LIKE|ILIKE)', corrected_where.group(1))
            original_columns = re.findall(r'(\w+)\s*(?:=|LIKE|ILIKE)', original_where.group(1))

            # Find new columns in corrected version
            new_columns = [col for col in corrected_columns if col not in original_columns]
            if new_columns:
                return new_columns[0]

        return ""

    def get_relevant_clarifications(self, user_email: str, question: str,
                                    entities: List[str]) -> Dict[str, Dict]:
        """
        Retrieve relevant clarifications based on the current question and entities.

        Args:
            user_email: Current user
            question: Current user question
            entities: List of entities (names, values) found in the question

        Returns:
            Dict mapping entities to their clarifications
        """
        clarifications = {}

        # Check each entity against stored clarifications
        for entity in entities:
            query = """
            SELECT DISTINCT 
                clarification_type,
                clarification_key,
                clarification_value,
                corrected_column,
                COUNT(*) as usage_count
            FROM QUERY_CLARIFICATIONS
            WHERE (user_email = :user_email OR user_email = 'GLOBAL')
            AND LOWER(clarification_key) = LOWER(:entity)
            AND created_at > DATEADD(month, -6, CURRENT_TIMESTAMP())
            GROUP BY 1, 2, 3, 4
            ORDER BY usage_count DESC
            LIMIT 1
            """

            with self.engine.connect() as conn:
                result = conn.execute(text(query), {
                    "user_email": user_email,
                    "entity": entity
                }).fetchone()

                if result:
                    clarifications[entity] = {
                        "type": result[0],
                        "value": result[2],
                        "column": result[3],
                        "usage_count": result[4]
                    }

        # Also check for similar questions
        similar_clarifications = self._get_similar_question_clarifications(
            user_email, question
        )
        clarifications.update(similar_clarifications)

        # Update last_used timestamp for used clarifications
        if clarifications:
            self._update_last_used(list(clarifications.keys()))

        return clarifications

    def _get_similar_question_clarifications(self, user_email: str,
                                             question: str) -> Dict[str, Dict]:
        """Find clarifications from similar questions"""
        # Simple similarity check - you could enhance this with better NLP
        keywords = [word.lower() for word in question.split() if len(word) > 3]

        if not keywords:
            return {}

        # Build dynamic WHERE clause for keyword matching
        keyword_conditions = " OR ".join([
            f"LOWER(original_question) LIKE '%{keyword}%'" for keyword in keywords
        ])

        query = f"""
        SELECT 
            clarification_key,
            clarification_type,
            clarification_value,
            corrected_column,
            original_question,
            COUNT(*) as match_count
        FROM QUERY_CLARIFICATIONS
        WHERE (user_email = :user_email OR user_email = 'GLOBAL')
        AND ({keyword_conditions})
        AND created_at > DATEADD(month, -6, CURRENT_TIMESTAMP())
        GROUP BY 1, 2, 3, 4, 5
        HAVING COUNT(*) >= 2  -- At least 2 keyword matches
        ORDER BY match_count DESC
        LIMIT 5
        """

        clarifications = {}
        with self.engine.connect() as conn:
            results = conn.execute(text(query), {"user_email": user_email}).fetchall()

            for row in results:
                if row[0] not in clarifications:
                    clarifications[row[0]] = {
                        "type": row[1],
                        "value": row[2],
                        "column": row[3],
                        "from_question": row[4],
                        "confidence": min(row[5] / len(keywords), 1.0)
                    }

        return clarifications

    def _update_last_used(self, clarification_keys: List[str]):
        """Update the last_used timestamp for clarifications"""
        if not clarification_keys:
            return

        placeholders = ", ".join([f":key{i}" for i in range(len(clarification_keys))])
        query = f"""
        UPDATE QUERY_CLARIFICATIONS
        SET last_used = CURRENT_TIMESTAMP()
        WHERE clarification_key IN ({placeholders})
        """

        params = {f"key{i}": key for i, key in enumerate(clarification_keys)}

        with self.engine.connect() as conn:
            conn.execute(text(query), params)
            conn.commit()

    def apply_clarifications_to_prompt(self, original_prompt: str,
                                       clarifications: Dict[str, Dict]) -> Tuple[str, str]:
        """
        Apply learned clarifications to enhance the prompt for SQL generation.

        Returns:
            Tuple of (enhanced_prompt, clarification_context)
        """
        if not clarifications:
            return original_prompt, ""

        # Build clarification context
        clarification_lines = []
        for entity, info in clarifications.items():
            if info["type"] == "column_mapping":
                clarification_lines.append(
                    f"- '{entity}' refers to {info['value']} (use column {info['column']})"
                )
            elif info["type"] == "table_correction":
                clarification_lines.append(
                    f"- Use table {info['value']} instead of {entity}"
                )

        clarification_context = (
                "\n\nBased on previous clarifications:\n" +
                "\n".join(clarification_lines) +
                "\n\nApply these clarifications when generating the SQL query."
        )

        # Enhanced prompt includes the clarification context
        enhanced_prompt = original_prompt + clarification_context

        return enhanced_prompt, clarification_context

    def get_clarification_stats(self, user_email: str) -> pd.DataFrame:
        """Get statistics about clarifications for analytics"""
        query = """
        SELECT 
            clarification_type,
            COUNT(*) as total_count,
            COUNT(DISTINCT clarification_key) as unique_entities,
            COUNT(DISTINCT DATE(created_at)) as days_active,
            MAX(created_at) as last_clarification
        FROM QUERY_CLARIFICATIONS
        WHERE user_email = :user_email
        GROUP BY clarification_type
        """

        with self.engine.connect() as conn:
            return pd.read_sql(query, conn, params={"user_email": user_email})

    def cleanup_old_clarifications(self, months: int = 12):
        """Clean up clarifications older than specified months"""
        query = """
        DELETE FROM QUERY_CLARIFICATIONS
        WHERE created_at < DATEADD(month, -:months, CURRENT_TIMESTAMP())
        AND last_used < DATEADD(month, -:months, CURRENT_TIMESTAMP())
        """

        with self.engine.connect() as conn:
            result = conn.execute(text(query), {"months": months})
            conn.commit()
            print(f"Cleaned up {result.rowcount} old clarifications")


def extract_entities_from_question(question: str, schema_text: str) -> List[str]:
    """
    Extract potential entities (names, values) from a question that might need clarification.
    Now extracts all possible 2-4 word phrases, regardless of capitalization, for robust clarification matching.
    """
    entities = []

    # Remove common SQL keywords and operators
    sql_keywords = {'select', 'from', 'where', 'and', 'or', 'group', 'by', 'order',
                    'having', 'limit', 'join', 'on', 'in', 'like', 'between', 'is',
                    'not', 'null', 'as', 'with', 'union', 'all', 'distinct', 'count',
                    'sum', 'avg', 'max', 'min', 'the', 'a', 'an', 'for', 'has', 'which'}

    # Extract quoted strings (keep this logic)
    quoted_strings = re.findall(r'"([^"]+)"|\'([^\']+)\'', question)
    for match in quoted_strings:
        entity = match[0] or match[1]
        if entity and entity.lower() not in sql_keywords:
            entities.append(entity)

    # NEW: Extract all possible 2-4 word phrases (sliding window, regardless of case)
    words = question.split()
    for window in range(4, 1, -1):  # Try 4-word, then 3-word, then 2-word
        for i in range(len(words) - window + 1):
            phrase = ' '.join(words[i:i+window])
            # Only add if not all words are SQL keywords
            if not all(w.lower() in sql_keywords for w in words[i:i+window]):
                entities.append(phrase)

    # Extract numbers that might be IDs or specific values
    numbers = re.findall(r'\b\d{4,}\b', question)  # 4+ digit numbers
    entities.extend(numbers)

    # Remove duplicates (case-insensitive)
    seen = set()
    unique_entities = []
    for entity in entities:
        key = entity.lower()
        if key not in seen:
            seen.add(key)
            unique_entities.append(entity)

    return unique_entities