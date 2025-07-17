# sections of system prompt
import os
import json
import datetime
import time
from datetime import timezone
import pandas as pd
from sqlalchemy import create_engine, text
from snowflake.sqlalchemy import URL
from dotenv import load_dotenv
from models import SessionLocal, QueryResult
from models import ChatHistory
from query_correction import enhance_query_correction, extract_query_components, \
    format_professional_suggestion
from snowflake_utils2 import query_snowflake, get_schema_details
from groq_utils2 import get_groq_response
import streamlit as st
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode
from PIL import Image
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from syn import correct_user_question_enhanced
from continuation_detection import check_and_handle_continuation
from sql_query_fixer import fix_generated_sql
from query_error_recovery import (
    handle_ui_based_error_recovery,
    process_ui_corrections
)
from clarification_memory import ClarificationMemory, extract_entities_from_question

# ------------------------
# Constants for Autosave
# ------------------------
AUTOSAVE_ENABLED = True
AUTOSAVE_INTERVAL = 60  # Backup save every 60 seconds (in case immediate save fails)
IMMEDIATE_SAVE_ENABLED = True  # Enable saving after each Q&A exchange

# ------------------------
# 1. Load environment vars
# ------------------------
load_dotenv()

# ------------------------
# 2. Streamlit configuration
# ------------------------
st.set_page_config(
    page_title="❄️ AI Data Assistant ❄️ ",
    page_icon="❄️",
    layout="wide"
)


# Apply custom CSS
def local_css(file_name):
    with open(file_name) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


local_css("style.css")


# ------------------------
# 3. Helper: get Snowflake private key
# ------------------------
def get_private_key_str():
    private_key_content = os.getenv("SNOWFLAKE_PRIVATE_KEY")
    if private_key_content:
        private_key_obj = serialization.load_pem_private_key(
            private_key_content.encode(),
            password=None,
            backend=default_backend()
        )
        der_private_key = private_key_obj.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return base64.b64encode(der_private_key).decode('utf-8')
    else:
        raise ValueError("Private key not found in environment variables")


# ------------------------
# 4. Connect to Snowflake
# ------------------------
def get_snowflake_connection():
    return create_engine(URL(
        account=os.getenv("SNOWFLAKE_ACCOUNT"),
        user=os.getenv("SNOWFLAKE_USER"),
        private_key=get_private_key_str(),
        database=os.getenv("SNOWFLAKE_DATABASE"),
        schema=os.getenv("SNOWFLAKE_SCHEMA"),
        warehouse=os.getenv("SNOWFLAKE_WAREHOUSE"),
        role=os.getenv("SNOWFLAKE_ROLE")
    ))


# ------------------------
# 5. User Authentication
# ------------------------
def authenticate_user(email, password):
    if not email.endswith("@ahs.com"):
        return False
    engine = get_snowflake_connection()
    with engine.connect() as conn:
        query = text("SELECT COUNT(*) FROM UserPasswordName WHERE username = :email AND password = :password")
        result = conn.execute(query, {"email": email, "password": password}).fetchone()
        return result[0] > 0


def needs_password_change(email):
    engine = get_snowflake_connection()
    with engine.connect() as conn:
        query = text("SELECT initial FROM UserPasswordName WHERE username = :email")
        result = conn.execute(query, {"email": email}).fetchone()
        return result[0] if result else False


def update_password(email, new_password):
    engine = get_snowflake_connection()
    with engine.connect() as conn:
        query = text("UPDATE UserPasswordName SET password = :new_password, initial = FALSE WHERE username = :email")
        conn.execute(query, {"new_password": new_password, "email": email})
        conn.commit()


# ------------------------
# Updated Login and Password Change Pages with Forest Background
# ------------------------

def get_base64_of_bin_file(bin_file):
    with open(bin_file, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode()


def set_png_as_page_bg(png_file):
    bin_str = get_base64_of_bin_file(png_file)
    page_bg_img = f"""
    <style>
    .stApp {{
        /* Dark gradient overlay for better legibility */
        background: linear-gradient(
            rgba(0, 0, 0, 0.4),
            rgba(0, 0, 0, 0.4)
        ), url("data:image/png;base64,{bin_str}") no-repeat center center fixed;
        background-size: cover;
    }}
    </style>
    """
    return page_bg_img


def login_page():
    # Set the forest background with gradient overlay
    st.markdown(set_png_as_page_bg('bg.jpg'), unsafe_allow_html=True)

    # Load Montserrat font from Google Fonts
    st.markdown(
        '<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600&display=swap" rel="stylesheet">',
        unsafe_allow_html=True
    )

    # Apply custom CSS
    st.markdown("""
    <style>
    /* Hide Streamlit's default UI elements */
    #MainMenu, footer, header {
        visibility: hidden;
    }

    /* Fade-in animation for the form container */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }

    /* Style the login box (the middle column) */
    .stColumn:nth-child(2) {
        max-width: 450px;
        margin: 0 auto;
        padding: 30px;
        margin-top: 100px;
        background-color: rgba(255, 255, 255, 0.75);
        border-radius: 10px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        backdrop-filter: blur(10px);
        animation: fadeIn 0.8s ease-in-out;
    }

    /* Heading style */
    .login-heading {
        font-family: 'Montserrat', sans-serif;
        font-size: 36px;
        font-weight: 700;
        text-align: center;
        margin-bottom: 30px;
        color: #000000;
        text-transform: uppercase;
    }

    /* Input labels */
    .custom-label {
        font-family: 'Montserrat','Segoe UI',Arial, sans-serif;
        font-size: 18px;
        color: #000;
        font-weight: 700;
        margin-bottom: 4px;
    }

    /* Input fields */
    .stTextInput > div > div > input {
        background-color: #F5F5F5;
        border: 1px solid #666666;
        padding: 14px 18px;
        border-radius: 5px;
        font-family: 'Montserrat', sans-serif;
        font-size: 18px;
        color: #000000;
        font-weight: 500;
        transition: border-color 0.3s ease;
    }

    /* Focus state for input fields */
    .stTextInput > div > div > input:focus {
        outline: none !important;
        border: 2px solid #1A237E;
    }

    /* Login button */
    .stButton > button {
        font-family: 'Montserrat', sans-serif;
        background-color: #1A237E;
        color: #FFFFFF;
        font-weight: 600;
        font-size: 18px;
        border: none;
        padding: 14px 0;
        border-radius: 5px;
        width: 100%;
        margin-top: 10px;
        transition: background-color 0.3s ease, transform 0.2s ease;
        cursor: pointer;
    }

    /* Hover effect on login button */
    .stButton > button:hover {
        background-color: #283593;
        transform: translateY(-2px);
    }

    /* Spacing between inputs */
    .stTextInput {
        margin-bottom: 18px;
    }

    /* Responsive design */
    @media (max-width: 768px) {
        .stColumn:nth-child(2) {
            margin-top: 50px;
            padding: 20px;
        }
    }

    /* Style for messages (e.g., Checking credentials...) */
    .message-text {
        color: #000000;
        font-weight: bold;
        font-family: 'Montserrat', sans-serif;
        text-align: center;
        margin-top: 10px;
        font-size: 18px;
    }
    .error-text {
        color: #FF0000;
        font-weight: bold;
        font-family: 'Montserrat', sans-serif;
        text-align: center;
        margin-top: 10px;
        font-size: 18px;
    }
    </style>
    """, unsafe_allow_html=True)

    # Center the login box with columns
    col1, col2, col3 = st.columns([1, 3, 1])
    with col2:
        # Heading
        st.markdown("<h1 class='login-heading'>Login</h1>", unsafe_allow_html=True)

        # Form elements with placeholder text and icons for intuitive UI
        st.markdown("<div class='custom-label'>Email</div>", unsafe_allow_html=True)
        email = st.text_input("Email", placeholder="✉️ Enter your email", key="login_email",
                              label_visibility="collapsed")
        st.markdown("<div class='custom-label'>Password</div>", unsafe_allow_html=True)
        password = st.text_input("Password", type="password", placeholder="🔒 Enter your password", key="login_password",
                                 label_visibility="collapsed")
        login_button = st.button("Login", key="login_button", use_container_width=True)

        # Placeholder for loading messages
        placeholder = st.empty()

        # Login logic with loading messages
        if login_button:
            placeholder.markdown("<div class='message-text'>Checking credentials...</div>", unsafe_allow_html=True)
            time.sleep(1)  # Simulate processing delay
            if authenticate_user(email, password):
                placeholder.markdown("<div class='message-text'>Loading your chat interface...</div>",
                                     unsafe_allow_html=True)
                time.sleep(1)  # Ensure the message is visible
                st.session_state["authenticated"] = True
                st.session_state["user"] = email
                st.rerun()
            else:
                placeholder.markdown("<div class='error-text'>Invalid credentials! Please try again.</div>",
                                     unsafe_allow_html=True)


def password_change_page():
    # Set the forest background with gradient overlay
    st.markdown(set_png_as_page_bg('bg.jpg'), unsafe_allow_html=True)

    # Load Montserrat font
    st.markdown(
        '<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600&display=swap" rel="stylesheet">',
        unsafe_allow_html=True
    )

    # Apply custom CSS
    st.markdown("""
    <style>
    /* Hide Streamlit's default UI elements */
    #MainMenu, footer, header {
        visibility: hidden;
    }

    /* Fade-in animation for the password change container */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }

    .stColumn:nth-child(2) {
        max-width: 450px;
        margin: 0 auto;
        padding: 30px;
        margin-top: 100px;
        background-color: rgba(255, 255, 255, 0.75);
        border-radius: 10px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        backdrop-filter: blur(10px);
        animation: fadeIn 0.8s ease-in-out;
    }

    /* Heading style */
    .password-heading {
        font-family: 'Montserrat', sans-serif;
        font-size: 36px;
        font-weight: 700;
        text-align: center;
        margin-bottom: 30px;
        color: #000000;
        text-transform: uppercase;
    }

    /* Input labels */
    .custom-label {
        font-family: 'Montserrat','Segoe UI',Arial, sans-serif;
        font-size: 18px;
        color: #000;
        font-weight: 700;
        margin-bottom: 4px;
    }

    /* Input fields */
    .stTextInput > div > div > input {
        background-color: #F5F5F5;
        border: 1px solid #666666;
        padding: 14px 18px;
        border-radius: 5px;
        font-family: 'Montserrat', sans-serif;
        font-size: 18px;
        color: #000000;
        font-weight: 500;
        transition: border-color 0.3s ease;
    }

    .stTextInput > div > div > input:focus {
        outline: none !important;
        border: 2px solid #1A237E;
    }

    /* Change password button */
    .stButton > button {
        font-family: 'Montserrat', sans-serif;
        background-color: #1A237E;
        color: #FFFFFF;
        font-weight: 600;
        font-size: 18px;
        border: none;
        padding: 14px 0;
        border-radius: 5px;
        width: 100%;
        margin-top: 10px;
        transition: background-color 0.3s ease, transform 0.2s ease;
        cursor: pointer;
    }

    .stButton > button:hover {
        background-color: #283593;
        transform: translateY(-2px);
    }

    /* Spacing between inputs */
    .stTextInput {
        margin-bottom: 18px;
    }

    /* Responsive design */
    @media (max-width: 768px) {
        .stColumn:nth-child(2) {
            margin-top: 50px;
            padding: 20px;
        }
    }
    </style>
    """, unsafe_allow_html=True)

    # Center the password box with columns
    col1, col2, col3 = st.columns([1, 3, 1])
    with col2:
        # Heading
        st.markdown("<h1 class='password-heading'>Change Password</h1>", unsafe_allow_html=True)

        # Grab the user's email from session
        email = st.session_state.get("user", "user@example.com")

        # Form elements with placeholder texts and icons for clarity
        st.markdown("<div class='custom-label'>Current Password</div>", unsafe_allow_html=True)
        current_password = st.text_input("Current Password", type="password", placeholder="🔒 Current Password",
                                         key="current_pwd", label_visibility="collapsed")
        st.markdown("<div class='custom-label'>New Password</div>", unsafe_allow_html=True)
        new_password = st.text_input("New Password", type="password", placeholder="🔒 New Password", key="new_pwd",
                                     label_visibility="collapsed")
        st.markdown("<div class='custom-label'>Confirm New Password</div>", unsafe_allow_html=True)
        confirm_password = st.text_input("Confirm New Password", type="password", placeholder="🔒 Confirm New Password",
                                         key="confirm_pwd", label_visibility="collapsed")
        change_button = st.button("Change Password", key="change_pwd_button", use_container_width=True)

        if change_button:
            if authenticate_user(email, current_password):
                if new_password == confirm_password:
                    update_password(email, new_password)
                    st.success("Password changed successfully!")
                    st.session_state["password_changed"] = True
                    st.rerun()
                else:
                    st.error("New passwords do not match!")
            else:
                st.error("Incorrect current password!")


# --- NEW FUNCTION: Autosave check ---
def maybe_autosave_chat():
    """Autosave the current chat if enough time has passed since last save."""
    current_time = time.time()

    # Initialize last_save_time if not present
    if "last_save_time" not in st.session_state:
        st.session_state.last_save_time = current_time
        return

    # Skip if no messages or if not enough time has passed
    if not st.session_state.chat_history or (current_time - st.session_state.last_save_time) < AUTOSAVE_INTERVAL:
        return

    # Avoid saving if the conversation hasn't changed
    if "last_saved_message_count" in st.session_state and len(
            st.session_state.chat_history) == st.session_state.last_saved_message_count:
        return

    # Save the current conversation with small tables
    save_chat_session_to_db(
        user=st.session_state["user"],
        messages=st.session_state.chat_history,
        persistent_dfs=st.session_state.persistent_dfs if "persistent_dfs" in st.session_state else [],
        chat_message_tables=st.session_state.chat_message_tables if "chat_message_tables" in st.session_state else {}
    )

    # Update last save time and message count
    st.session_state.last_save_time = current_time
    st.session_state.last_saved_message_count = len(st.session_state.chat_history)


def save_after_exchange():
    """Save the conversation immediately after each user-assistant exchange."""
    if not st.session_state.chat_history:
        return

    # Save the current conversation with small tables
    save_chat_session_to_db(
        user=st.session_state["user"],
        messages=st.session_state.chat_history,
        persistent_dfs=st.session_state.persistent_dfs if "persistent_dfs" in st.session_state else [],
        chat_message_tables=st.session_state.chat_message_tables if "chat_message_tables" in st.session_state else {}
    )

    # Update tracking variables
    st.session_state.last_save_time = time.time()
    st.session_state.last_saved_message_count = len(st.session_state.chat_history)


# --- MODIFIED save_chat_session_to_db ---
def save_chat_session_to_db(user, messages, persistent_dfs=None, chat_message_tables=None):
    """Save the current conversation to DB, storing small DataFrames (under 1000 rows) as JSON."""
    if not messages:
        return

    # Generate a better title from first user message (not system prompt)
    user_messages = [msg for msg in messages if msg["role"] == "user"]
    if user_messages:
        title = user_messages[0]["content"][:30] + "..."
    else:
        title = "New Chat (" + datetime.datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S') + ")"

    # Store small tables data
    small_tables = {}
    if persistent_dfs and chat_message_tables:
        for msg_idx, df_idx in chat_message_tables.items():
            if df_idx < len(persistent_dfs):
                df = persistent_dfs[df_idx]
                if len(df) <= 1000:  # Only store tables with 1000 rows or fewer
                    # Convert DataFrame to dict and store with message index as key
                    small_tables[str(msg_idx)] = {
                        'data': df.to_dict(orient='records'),
                        'columns': df.columns.tolist()
                    }

    messages_json = json.dumps(messages)
    small_tables_json = json.dumps(small_tables) if small_tables else "{}"
    df_mappings_json = json.dumps(chat_message_tables) if chat_message_tables else "{}"

    db_session = SessionLocal()
    try:
        # Check if we already have a chat with the same ID in session
        if "current_chat_id" in st.session_state:
            existing_chat = db_session.query(ChatHistory).filter(
                ChatHistory.id == st.session_state.current_chat_id).first()
            if existing_chat:
                existing_chat.title = title
                existing_chat.timestamp = datetime.datetime.now(timezone.utc)
                existing_chat.messages = messages_json
                existing_chat.persistent_df_paths = "[]"  # Empty array as JSON
                existing_chat.persistent_df_mappings = df_mappings_json
                existing_chat.small_tables_data = small_tables_json  # Save small tables
                db_session.commit()
                return

        # Create new chat record if no existing one
        chat_record = ChatHistory(
            user=user,
            title=title,
            timestamp=datetime.datetime.now(timezone.utc),
            messages=messages_json,
            persistent_df_paths="[]",  # Empty array as JSON
            persistent_df_mappings=df_mappings_json,
            small_tables_data=small_tables_json  # Save small tables
        )
        db_session.add(chat_record)
        db_session.commit()

        # Store the ID of this chat for future updates
        st.session_state.current_chat_id = chat_record.id
    except Exception as e:
        print(f"Error saving chat session: {e}")
    finally:
        db_session.close()


def load_chat_sessions_for_user(user_email):
    """Return a list of all conversation dicts for this user."""
    db_session = SessionLocal()
    sessions = []
    try:
        results = db_session.query(ChatHistory).filter(ChatHistory.user == user_email).all()
        for s in results:
            # Include small_tables_data in the returned sessions
            small_tables_data = {}
            if hasattr(s, 'small_tables_data') and s.small_tables_data:
                try:
                    small_tables_data = json.loads(s.small_tables_data)
                except:
                    small_tables_data = {}

            sessions.append({
                "id": s.id,
                "user": s.user,
                "title": s.title,
                "timestamp": s.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "messages": json.loads(s.messages),
                "persistent_df_paths": [],  # Empty list for compatibility
                "small_tables_data": small_tables_data
            })
    except Exception as e:
        print(f"Error loading chat sessions: {e}")
    finally:
        db_session.close()
    return sessions


# 5. MODIFY the load_conversation_into_session function
def load_conversation_into_session(conversation):
    """Load the chosen conversation into session_state so user can continue."""
    # Load the full conversation for context (used for generating responses)
    st.session_state.messages = conversation["messages"]
    # For display, filter out the system message
    st.session_state.chat_history = [msg for msg in conversation["messages"] if msg["role"] != "system"]

    # Initialize empty persistent_dfs
    st.session_state.persistent_dfs = []

    # Initialize empty chat_message_tables
    st.session_state.chat_message_tables = {}

    # Process small tables if available
    if "small_tables_data" in conversation and conversation["small_tables_data"]:
        small_tables = conversation["small_tables_data"]
        for msg_idx_str, table_data in small_tables.items():
            # Convert string key to integer
            msg_idx = int(msg_idx_str)

            # Create DataFrame from saved data
            if 'data' in table_data and 'columns' in table_data:
                df = pd.DataFrame(table_data['data'], columns=table_data['columns'])

                # Add to persistent_dfs
                df_idx = len(st.session_state.persistent_dfs)
                st.session_state.persistent_dfs.append(df)

                # Map to message
                st.session_state.chat_message_tables[msg_idx] = df_idx

    # Store the conversation ID so we can update it rather than create new ones
    st.session_state.current_chat_id = conversation["id"]
    st.session_state.last_saved_message_count = len(conversation["messages"])
    st.session_state.last_save_time = time.time()


# ---------------------------------------------
# 7. Query Logging (existing from your code)
# ---------------------------------------------
def sync_sqlite_to_snowflake():
    try:
        DATABASE_URL = "sqlite:///log.db"
        local_engine = create_engine(DATABASE_URL)
        table_name = "query_result"
        with local_engine.connect() as conn:
            df = pd.read_sql(f"SELECT * FROM {table_name} WHERE synced_to_snowflake = FALSE", conn)
        if df.empty:
            print("No new data to sync.")
            return
        SNOWFLAKE_ACCOUNT = os.getenv("SNOWFLAKE_ACCOUNT")
        SNOWFLAKE_USER = os.getenv("SNOWFLAKE_USER")
        private_key = get_private_key_str()
        SNOWFLAKE_DATABASE = os.getenv("SNOWFLAKE_DATABASE")
        SNOWFLAKE_SCHEMA = os.getenv("SNOWFLAKE_SCHEMA")
        SNOWFLAKE_WAREHOUSE = os.getenv("SNOWFLAKE_WAREHOUSE")
        SNOWFLAKE_ROLE = os.getenv("SNOWFLAKE_ROLE")
        if not all([SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER, private_key,
                    SNOWFLAKE_DATABASE, SNOWFLAKE_SCHEMA, SNOWFLAKE_WAREHOUSE, SNOWFLAKE_ROLE]):
            print("Missing Snowflake credentials in environment variables.")
            return
        snowflake_engine = create_engine(URL(
            account=SNOWFLAKE_ACCOUNT,
            user=SNOWFLAKE_USER,
            private_key=private_key,
            database=SNOWFLAKE_DATABASE,
            schema=SNOWFLAKE_SCHEMA,
            warehouse=SNOWFLAKE_WAREHOUSE,
            role=SNOWFLAKE_ROLE
        ))
        snowflake_table_name = "Logtable"
        print(f"Syncing data to Snowflake table: {snowflake_table_name}")
        with snowflake_engine.connect() as conn:
            df.to_sql(
                name=snowflake_table_name,
                con=conn,
                if_exists='append',
                index=False,
                method='multi'
            )
            print(f"Synced {len(df)} new rows to Snowflake.")
            with local_engine.connect() as local_conn:
                for id in df['id']:
                    local_conn.execute(
                        text(f"UPDATE {table_name} SET synced_to_snowflake = TRUE WHERE id = :id"),
                        {"id": id}
                    )
                local_conn.commit()
    except Exception as e:
        print(f"Error syncing data to Snowflake: {e}")


def save_query_result(user_query, natural_language_response, result, sql_query, response_text,
                      tokens_first_call=None, tokens_second_call=None, total_tokens_used=None, error_message=None):
    db_session = SessionLocal()
    try:
        query_result = QueryResult(
            query=user_query,
            answer=str(natural_language_response) if natural_language_response else None,
            sfresult=str(result) if result else None,
            sqlquery=str(sql_query) if sql_query else None,
            raw_response=str(response_text),
            tokens_first_call=tokens_first_call,
            tokens_second_call=tokens_second_call,
            total_tokens_used=total_tokens_used,
            error_message=str(error_message) if error_message else None
        )
        db_session.add(query_result)
        db_session.commit()
        sync_sqlite_to_snowflake()
    except Exception as e:
        print(f"Error saving query and result to database: {e}")
    finally:
        db_session.close()


# ---------------------------------------------
# 8. Main Application
# ---------------------------------------------
def main_app():
    if "user" in st.session_state:
        # username = st.session_state["user"].split("@")[0]
        username = st.session_state["user"]

        st.markdown(
            f"""
            <style>
            /* Container aligned to the right, near the 'Deploy' button */
            .username-container {{
                display: flex;
                justify-content: flex-end;
                margin-top: -54px; /* Adjust as needed */
                margin-right: -5px; /* Adjust spacing from right edge */
            }}
            /* Black text, smaller size to match 'Deploy' */
            .black-text {{
                font-size: 16px;
                color: black;
                font-weight: 600;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }}
            </style>
            <div class="username-container">
                <div class="black-text">
                    Logged in as: {username}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    import re

    def display_query_corrections(correction_suggestions, original_query):
        """
        Create interactive UI for query corrections

        Args:
            correction_suggestions (dict): Suggestions for query corrections
            original_query (str): Original SQL query

        Returns:
            str or None: Corrected query if a suggestion is selected
        """
        # Create a container for corrections
        correction_container = st.container()

        with correction_container:
            st.warning("No results found. Did you mean:")

            # Track selected corrections
            selected_corrections = {}

            # Display corrections for each suggestion
            for i, suggestion in enumerate(correction_suggestions['suggestions']):
                st.write(f"In column '{suggestion['column']}', '{suggestion['original_value']}' might be incorrect.")

                # Create a selectbox for each suggestion
                selected_value = st.selectbox(
                    f"Select a correction for {suggestion['column']}",
                    ['Original Value'] + suggestion['suggested_values'],
                    key=f"correction_{i}"
                )

                # If a different value is selected, store it
                if selected_value != 'Original Value':
                    selected_corrections[suggestion['column']] = selected_value

            # Correction button
            if st.button("Apply Corrections"):
                # Create a corrected query
                corrected_query = original_query

                # Replace values in the query
                for column, new_value in selected_corrections.items():
                    # Use regex to replace the specific column's value
                    # Handles both quoted and unquoted column names
                    corrected_query = re.sub(
                        rf'("{column}"\s*=\s*[\'"]){suggestion["original_value"]}([\'"])',
                        rf'\1{new_value}\2',
                        corrected_query
                    )

                return corrected_query

        return None

    # Modify your existing query execution logic
    def execute_corrected_query(corrected_query):
        """
        Execute the corrected query

        Args:
            corrected_query (str): SQL query with corrections

        Returns:
            list or dict: Query results
        """
        try:
            # Your existing query execution logic
            result = query_snowflake(corrected_query, st.session_state["user"])
            return result
        except Exception as e:
            st.error(f"Error executing corrected query: {e}")
            return None

    def load_all_instructions(engine):
        """
        Load ALL instructions from INSTRUCTIONS_NEW table as a shared knowledge base
        Only loads instructions where DELETED = FALSE
        """
        query = """
        SELECT "INSTRUCTION" 
        FROM ATI_AI_USAGE.INSTRUCTIONS_NEW
        WHERE "DELETED" = FALSE
        ORDER BY "INSTRUCTION"
        """

        try:
            with engine.connect() as conn:
                result = pd.read_sql(query, conn)

            if result.empty:
                return []

            # Handle case sensitivity
            for col in result.columns:
                if col.upper() == 'INSTRUCTION':
                    return result[col].tolist()

            return []

        except Exception as e:
            print(f"Error loading instructions: {e}")
            return []

    def format_instructions_for_prompt(instructions):
        """
        Format instructions into a clear prompt section
        """
        if not instructions:
            return ""

        formatted = "\n\nSHARED KNOWLEDGE BASE (from all users):\n"
        for i, instruction in enumerate(instructions, 1):
            formatted += f"{i}. {instruction}\n"

        formatted += "\nApply these rules when generating SQL queries where relevant.\n"

        return formatted

    def enhance_system_prompt_with_instructions(base_prompt, instructions):
        """
        Enhance the system prompt by adding shared instructions
        """
        if not instructions:
            return base_prompt

        instruction_section = format_instructions_for_prompt(instructions)

        if "{schema_text}" in base_prompt:
            enhanced_prompt = base_prompt.replace(
                "{schema_text}",
                "{schema_text}" + instruction_section
            )
        else:
            enhanced_prompt = base_prompt + instruction_section

        return enhanced_prompt

    def format_query_correction_response(correction_suggestions, original_query):
        """
        Format query correction suggestions into a user-friendly message

        Args:
            correction_suggestions (dict): Suggestions for query corrections
            original_query (str): Original SQL query

        Returns:
            str: Formatted suggestion message
        """
        # Start with a clear, informative header
        suggestion_message = "🔍 Query Correction Suggestions:\n\n"

        # Add details about each suggestion
        for suggestion in correction_suggestions['suggestions']:
            suggestion_message += f"• Column: *{suggestion['column']}*\n"
            suggestion_message += f"  Original Value: `{suggestion['original_value']}`\n"
            suggestion_message += f"  Possible Correct Values:\n"

            # List possible corrections
            for value in suggestion['suggested_values']:
                suggestion_message += f"    - {value}\n"

            suggestion_message += "\n"

        # Add a helpful footer
        suggestion_message += "**Tip:** Consider using one of the suggested values to improve your query results.\n\n"
        suggestion_message += f"*Original Query:* ```sql\n{original_query}\n```"

        return suggestion_message

    def create_correction_dataframe(correction_suggestions):
        """
        Create a DataFrame to display correction suggestions

        Args:
            correction_suggestions (dict): Suggestions for query corrections

        Returns:
            pandas.DataFrame: Formatted suggestions DataFrame
        """
        import pandas as pd

        # Prepare data for DataFrame
        correction_data = []
        for suggestion in correction_suggestions['suggestions']:
            for suggested_value in suggestion['suggested_values']:
                correction_data.append({
                    'Column': suggestion['column'],
                    'Original Value': suggestion['original_value'],
                    'Suggested Value': suggested_value
                })

        # Create DataFrame
        df = pd.DataFrame(correction_data)
        return df

    def get_cached_schema_details(user_email):
        """Get schema details from cache or database"""
        cache_key = f"schema_{user_email}"

        # Check if schema is already in session state cache
        if cache_key in st.session_state:
            return st.session_state[cache_key]

        # If not in cache, retrieve from database
        schema_details = get_schema_details(user_email)

        # Check if we got a valid schema (not an error)
        if isinstance(schema_details, dict) and "error" not in schema_details:
            # Cache the result in session state
            st.session_state[cache_key] = schema_details

        return schema_details

    if "last_sql_query" not in st.session_state:
        st.session_state.last_sql_query = None
    if "awaiting_continuation_choice" not in st.session_state:
        st.session_state.awaiting_continuation_choice = False
    if "continuation_options" not in st.session_state:
        st.session_state.continuation_options = None
    if "total_tokens" not in st.session_state:
        st.session_state.total_tokens = 0
    if "persistent_dfs" not in st.session_state:
        st.session_state.persistent_dfs = []
    if "messages" not in st.session_state:
        st.session_state.messages = []
        st.session_state.chat_history = []

    # ---- AUTOSAVE CHECK ----
    if AUTOSAVE_ENABLED:
        maybe_autosave_chat()

    # -------------------------------
    #  A) SIDEBAR: Show Chat History
    # -------------------------------
    def delete_chat_by_id(chat_id):
        db_session = SessionLocal()
        try:
            db_session.query(ChatHistory).filter(ChatHistory.id == chat_id).delete()
            db_session.commit()
        except Exception as e:
            st.error(f"Error deleting chat: {e}")
        finally:
            db_session.close()

    with st.sidebar:
        logo = Image.open("4Logo.png")  # Your logo file
        st.image(logo, width=400)
        st.markdown("## Your Chat History")

        # 1. Load all user's past conversations from DB
        user_email = st.session_state["user"]
        user_conversations = load_chat_sessions_for_user(user_email)

        # 2. Group conversations by date
        if user_conversations:
            # Sort conversations by timestamp (newest first)
            user_conversations.sort(key=lambda x: x['timestamp'], reverse=True)

            # Group conversations by date
            conversations_by_date = {}
            for conv in user_conversations:
                # Extract just the date part from the timestamp (format: YYYY-MM-DD)
                date = conv['timestamp'].split(' ')[0]
                if date not in conversations_by_date:
                    conversations_by_date[date] = []
                conversations_by_date[date].append(conv)
            import datetime
            # Display conversations grouped by date
            for date, convs in conversations_by_date.items():
                # Format date for display (e.g., "15-3-25" instead of "2025-03-15")
                display_date = datetime.datetime.strptime(date, "%Y-%m-%d").strftime("%d-%m-%y")

                # Create a date header with custom styling
                st.markdown(f"""
                <div style="background-color: #f0f2f6; padding: 5px; border-radius: 5px; margin-bottom: 5px;">
                    <span style="font-weight: bold; color: #1A237E;">{display_date}</span>
                </div>
                """, unsafe_allow_html=True)

                # Display conversations for this date
                for conv in convs:
                    # Just show the title without the timestamp since we're already grouped by date
                    button_label = conv['title']
                    col1, col2 = st.columns([8, 1])
                    with col1:
                        if st.button(button_label, key=f"btn_{conv['id']}"):
                            load_conversation_into_session(conv)
                            st.rerun()
                    with col2:
                        if st.button("🗑️", key=f"delete_{conv['id']}", help="Delete this chat"):
                            delete_chat_by_id(conv['id'])
                            st.rerun()

        st.write("---")
        # 3. New Chat button
        if st.button("🆕 New Chat"):
            # Save the current conversation (if any) with small tables
            if st.session_state.chat_history:
                save_chat_session_to_db(
                    user=st.session_state["user"],
                    messages=st.session_state.chat_history,
                    persistent_dfs=st.session_state.persistent_dfs if "persistent_dfs" in st.session_state else [],
                    chat_message_tables=st.session_state.chat_message_tables if "chat_message_tables" in st.session_state else {}
                )
            # Clear the active session
            st.session_state.pop("messages", None)
            st.session_state.pop("chat_history", None)
            st.session_state.pop("persistent_dfs", None)
            st.session_state.pop("chat_message_tables", None)
            st.session_state.pop("current_chat_id", None)
            st.session_state.pop("last_saved_message_count", None)
            st.rerun()

        # Clear History button
        if st.button("🗑️ Clear History"):
            delete_chat_by_id(st.session_state.current_chat_id)
            st.success("Chat history cleared!")
            st.rerun()

        # 4. Logout button
        if st.button("Logout"):
            # Clear all session state variables related to chat and queries
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            # Reinitialize only the authentication state
            st.session_state["authenticated"] = False
            st.rerun()


    # ----------------------------------
    #  B) MAIN: Chat interface
    # ----------------------------------
    st.markdown("""
        <style>
            div.streamlit-expanderHeader {
                font-weight: bold !important;
                font-size: 18px !important; /* Bigger and bolder */
                font-family: 'Arial', sans-serif !important; /* Clean, professional font */
                color: #1A237E !important; /* Dark blue for better visibility */
            }
            div[data-testid="stExpander"] {
                max-width: 500px; /* Adjust width */
                margin-left: 0; /* Align to left */
            }
        </style>
    """, unsafe_allow_html=True)

    # UI Components
    st.title("❄️ AI Data Assistant ❄️")
    st.caption("Ask me about your business analytics queries")

    # Expander with optimized size and font
    with st.expander("📝 Not sure what to ask? Click here for sample questions"):
        st.markdown("""
            <div style="
                background: linear-gradient(to right, #e0f7fa, #b2ebf2);
                border-radius: 10px;
                padding: 15px;">
                <ul style="margin-bottom: 5px;">
                    <li><b>Paid invoice summary details:</b> "Paid Invoice Summary"</li>
                    <li><b>Purchase order details:</b> "Fetch all details of home depot where goods are invoiced"</li>
                    <li><b>Vendor Info:</b> "Vendor Details"</li>
                    <li><b>Purchase requisition details:</b> "Give me a count of purchase requisition for the year 2025"</li>
                </ul>
                <p style="color: #00838f; font-size: 0.9em; margin-bottom: 0;">
                    If you're unsure what to ask, feel free to use the sample questions above or rephrase them to get the insights you need.
                </p>
            </div>
        """, unsafe_allow_html=True)

    def fetch_system_prompt_sections():
        """Fetch all active system prompt sections from Snowflake in order"""
        engine = get_snowflake_connection()
        query = """
        SELECT section_name, prompt_text 
        FROM system_prompt_new
        ORDER BY section_order ASC
        """

        with engine.connect() as conn:
            result = pd.read_sql(query, conn)

        if result.empty:
            raise ValueError("No system prompt sections found in database")

        # Combine all sections into one complete prompt
        combined_prompt = ""
        for _, row in result.iterrows():
            combined_prompt += row['prompt_text'] + "\n\n"

        return combined_prompt.strip()

    # Prepare the system prompt for your LLM
    schema_details = get_cached_schema_details(st.session_state["user"])
    if "error" in schema_details:
        st.error(schema_details["error"])
        st.stop()

    schema_text = ""
    for table, columns in schema_details.items():
        schema_text += f"Table: {table}\n"
        schema_text += "Columns:\n"
        for col, dtype in columns:
            schema_text += f"  - {col} (Data Type: {dtype})\n"
        schema_text += "\n"

    combined_template = fetch_system_prompt_sections()

    # Always prepare base version (without instructions)
    base_system_prompt = combined_template.format(
        schema_text=schema_text,
        user_email=st.session_state["user"]
    )

    # Prepare enhanced version with instructions
    try:
        engine = get_snowflake_connection()
        all_instructions = load_all_instructions(engine)

        if all_instructions:
            enhanced_template = enhance_system_prompt_with_instructions(
                combined_template,
                all_instructions
            )
            enhanced_system_prompt = enhanced_template.format(
                schema_text=schema_text,
                user_email=st.session_state["user"]
            )
        else:
            # If no instructions, use base prompt
            enhanced_system_prompt = base_system_prompt

    except Exception as e:
        print(f"Error loading instructions, using base prompt: {e}")
        enhanced_system_prompt = base_system_prompt

    # Store system prompt in session state
    if "system_prompt" not in st.session_state:
        st.session_state.base_system_prompt = base_system_prompt
        st.session_state.enhanced_system_prompt = enhanced_system_prompt
        st.session_state.system_prompt = enhanced_system_prompt

        # Create chat_message_columns map to track which messages have tables
    if "chat_message_tables" not in st.session_state:
        st.session_state.chat_message_tables = {}
    if "awaiting_error_clarification" not in st.session_state:
        st.session_state.awaiting_error_clarification = False
    if "error_clarification_data" not in st.session_state:
        st.session_state.error_clarification_data = {}
    if "ui_corrections" not in st.session_state:
        st.session_state.ui_corrections = {}
    if "awaiting_correction_submit" not in st.session_state:
        st.session_state.awaiting_correction_submit = False
    if "pending_corrected_sql" not in st.session_state:
        st.session_state.pending_corrected_sql = None

        # Initialize messages without system prompt
    if not st.session_state.messages:
        st.session_state.messages = []  # Don't include system prompt here
        st.session_state.chat_history = []

        # Function to make API calls with system prompt

    def get_groq_response_with_system(conversation_messages):
        """Prepends the system prompt to conversation messages and calls the API"""

        # Use base prompt during error recovery/clarification
        if (st.session_state.get("awaiting_error_clarification", False) or
                st.session_state.get("awaiting_correction_submit", False) or
                st.session_state.get("pending_corrected_sql")):
            system_prompt = st.session_state.get("base_system_prompt", st.session_state.system_prompt)
        else:
            system_prompt = st.session_state.get("enhanced_system_prompt", st.session_state.system_prompt)

        full_messages = [{"role": "system", "content": system_prompt}] + conversation_messages
        return get_groq_response(full_messages)

        # Function to handle table display based on row count

    def get_groq_response_with_clarifications(conversation_messages, user_email, current_question, schema_text):
        """
        Enhanced version that checks for previous clarifications before generating SQL.
        """
        # Initialize clarification memory
        memory = ClarificationMemory(get_snowflake_connection())

        # Extract entities from the current question
        entities = extract_entities_from_question(current_question, schema_text)

        # Get relevant clarifications
        clarifications = memory.get_relevant_clarifications(user_email, current_question, entities)

        # If we have clarifications, enhance the system prompt
        if clarifications:
            # Create enhanced messages with clarification context
            enhanced_messages = conversation_messages.copy()

            # Find the user message and enhance it
            for i, msg in enumerate(enhanced_messages):
                if msg["role"] == "user" and current_question in msg["content"]:
                    enhanced_prompt, clarification_context = memory.apply_clarifications_to_prompt(
                        msg["content"], clarifications
                    )
                    enhanced_messages[i] = {"role": "user", "content": enhanced_prompt}

                    # Show what clarifications were applied
                    applied_items = []
                    for entity, info in clarifications.items():
                        if info["type"] == "column_mapping":
                            applied_items.append(f"'{entity}' → {info['value']}")

                    if applied_items:
                        st.info(f"📚 Applied learned clarifications: {', '.join(applied_items)}")
                    break

            # Call the original function with enhanced messages
            return get_groq_response(
                [{"role": "system", "content": st.session_state.system_prompt}] + enhanced_messages
            )
        else:
            # No clarifications found, proceed normally
            return get_groq_response(
                [{"role": "system", "content": st.session_state.system_prompt}] + conversation_messages
            )

    def display_table_with_size_handling(df, message_index, df_idx):
        """
        Display table with appropriate handling based on row size:
        - For tables > 100,000 rows: Show only download button
        - For tables <= 100,000 rows: Show download button + AgGrid table
        - For tables > 1000 rows: Show warning about temporary availability
        - For tables <= 1000 rows: Display normally (these are saved in session)

        Parameters:
        - df: pandas DataFrame to display
        - message_index: Current message index for unique key generation
        - df_idx: DataFrame index in persistent store
        """
        # Always provide download option regardless of size
        csv = df.to_csv(index=False).encode("utf-8")

        # Check row count to determine display method and warnings
        num_rows = len(df)

        if num_rows > 1000:
            # Warning for large tables that won't be saved
            st.warning(
                "⚠️ **Download is only available now!** This data is too large to save with your chat history and won't be accessible for download after navigating away from this page.",
                icon="⚠️")

        st.download_button(
            label="Download Full Dataset as CSV",
            data=csv,
            file_name=f"query_result_{message_index}.csv",
            mime="text/csv",
            key=f"download_csv_{message_index}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        )

        if num_rows <= 200000:
            # For tables under the threshold, show interactive AgGrid
            gb = GridOptionsBuilder.from_dataframe(df)
            gb.configure_default_column(filter=True, sortable=True)
            gridOptions = gb.build()
            AgGrid(
                df,
                gridOptions=gridOptions,
                height=400,
                width='100%',
                key=f"grid_{message_index}_{df_idx}_{id(df)}",  # Unique key
                update_mode=GridUpdateMode.VALUE_CHANGED
            )

    # Display the chat history in proper order, with tables integrated
    message_index = 0
    for msg_idx, msg in enumerate(st.session_state.chat_history):
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

            # Check if this message has a corresponding table to display
            if msg["role"] == "assistant" and message_index in st.session_state.chat_message_tables:
                df_idx = st.session_state.chat_message_tables[message_index]
                if df_idx < len(st.session_state.persistent_dfs):
                    df = st.session_state.persistent_dfs[df_idx]

                    # Only display if the dataframe is not empty
                    if not df.empty:
                        # Use our new function to handle display based on size
                        display_table_with_size_handling(df, message_index, df_idx)

        if msg["role"] == "assistant":
            message_index += 1
            # (REMOVE the clarification UI block from here)
            # (REMOVE the pending_corrected_sql execution block from here)

    # ---- END chat history rendering loop ----

    # Display correction UI if waiting for clarification (moved outside loop)
    if st.session_state.awaiting_error_clarification and "error_clarification_data" in st.session_state:
        # Create a unique container for the correction UI
        correction_container = st.container()
        with correction_container:
            with st.chat_message("assistant"):
                filter_info = st.session_state.error_clarification_data.get("filter_info", {})
                # --- CLEANER INSTRUCTION BLOCK ---
                st.markdown(
                    '''<div style="background-color:#f8fafc; border-radius:10px; padding:18px 20px 14px 20px; margin-bottom:18px; border:1px solid #e0e7ef; font-size:16px;">
                    <span style="font-size:18px; font-weight:600; color:#f5a623; vertical-align:middle; margin-right:8px;">&#128712;</span>
                    <span style="font-weight:600; color:#222;">I couldn't find any results for your query.</span><br><br>
                    <span style="color:#222;">I searched with the following:</span><br>
                    <ul style="margin:8px 0 8px 18px;">
                ''' +
                    ''.join([f'<li><b>{i}. {filter_item["value"]}</b> in column <b>{filter_item["column"]}</b></li>' for
                             i, filter_item in enumerate(filter_info.get("filters", []), 1)]) +
                    f'<li>Table used: <b>{filter_info.get("table", "Unknown")}</b></li>' +
                    '''</ul>
                    <div style="margin-top:10px; color:#333;">
                        To help me find the correct data, please tell me what each value represents. For example:<br>
                        <span style="color:#666; font-size:15px;">
                        &bull; "2500148150 is a project ID"<br>
                        &bull; "Elite Disaster Team is a vendor name"<br>
                        &bull; "Use AP_DETAILS table instead"<br>
                        </span>
                        <br>Or type <b>"correct"</b> if everything looks right.
                    </div>
                    </div>''', unsafe_allow_html=True)
                # --- END CLEANER INSTRUCTION BLOCK ---
                with st.form(key="correction_form"):
                    corrections = {}
                    for i, filter_item in enumerate(filter_info.get("filters", []), 1):
                        col1, col2 = st.columns([1, 2])
                        with col1:
                            st.markdown(f"{i}. **{filter_item['value']}**")
                        with col2:
                            correction = st.text_input(
                                label=f"Correction for {filter_item['value']}",
                                key=f"correction_filter_{i}",
                                placeholder="Leave empty if correct",
                                label_visibility="collapsed"
                            )
                            if correction:
                                corrections[f"{filter_item['column']}:{filter_item['value']}"] = correction
                    col1, col2 = st.columns([1, 2])
                    with col1:
                        st.markdown(
                            f"**{len(filter_info.get('filters', [])) + 1}. {filter_info.get('table', 'Unknown')}**")
                    with col2:
                        table_correction = st.text_input(
                            label="Table correction",
                            key="correction_table",
                            placeholder="Leave empty if correct",
                            label_visibility="collapsed"
                        )
                        if table_correction:
                            corrections["table"] = table_correction
                    st.markdown(
                        "**NOTE:** Leave the box empty for the corresponding thing if you feel everything is correct with that particular case")
                    submitted = st.form_submit_button("Submit Corrections", type="primary")
                    if submitted:
                        recovery_result = process_ui_corrections(
                            corrections,
                            filter_info,
                            st.session_state.error_clarification_data["original_sql"],
                            schema_text,
                            get_groq_response_with_system,
                            snowflake_engine=get_snowflake_connection(),  # ADD THIS
                            user_email=st.session_state["user"],  # ADD THIS
                            original_question=st.session_state.error_clarification_data["original_prompt"]  # ADD THIS
                        )
                        st.session_state.awaiting_error_clarification = False
                        if recovery_result.get("needs_retry") and recovery_result.get("fixed_sql"):
                            st.session_state.pending_corrected_sql = {
                                "sql": recovery_result["fixed_sql"],
                                "original_prompt": st.session_state.error_clarification_data["original_prompt"],
                                "corrections": recovery_result.get("corrections_applied", {})
                            }
                        save_after_exchange()
                        st.rerun()

    def clean_llm_response(response: str) -> str:

        """
        Cleans up LLM responses for consistent display:
        - Removes markdown formatting like *, _, `
        - Fixes spacing after commas
        - Normalizes multiple spaces
        """
        cleaned = re.sub(r'[*_`]', '', response)
        cleaned = re.sub(r',(?=\S)', ', ', cleaned)
        cleaned = re.sub(r'\s{2,}', ' ', cleaned)
        return cleaned.strip()

    def extract_ranking_criteria(sql_query: str) -> str:
        """
        Analyze SQL query to determine the ranking/sorting criteria
        Returns a human-readable description of the criteria
        """
        sql_upper = sql_query.upper()

        # Check ORDER BY clause
        order_by_match = re.search(r'ORDER\s+BY\s+([^;]+?)(?:DESC|ASC|LIMIT|$)', sql_upper, re.IGNORECASE)

        if order_by_match:
            order_clause = order_by_match.group(1).strip()

            # Common patterns
            if 'COUNT(' in order_clause:
                if 'DISTINCT' in order_clause:
                    # Extract what's being counted
                    count_match = re.search(r'COUNT\s*\(\s*DISTINCT\s+(\w+)', order_clause)
                    if count_match:
                        column = count_match.group(1).lower()
                        return f"based on the count of unique {column.replace('_', ' ')}s"
                else:
                    return "based on the total count"

            elif 'SUM(' in order_clause:
                sum_match = re.search(r'SUM\s*\(\s*(\w+)', order_clause)
                if sum_match:
                    column = sum_match.group(1).lower()
                    return f"based on the total {column.replace('_', ' ')}"

            elif 'MAX(' in order_clause:
                return "based on the maximum value"

            elif 'MIN(' in order_clause:
                return "based on the minimum value"

            elif 'AVG(' in order_clause:
                return "based on the average"

        # Check if there's a LIMIT without clear ordering (implies some kind of top/max query)
        if 'LIMIT' in sql_upper and 'GROUP BY' in sql_upper:
            return "based on the grouping and aggregation used"

        return ""

    def format_llm_response(text: str) -> str:
        """
        Formats LLM responses into clean HTML using preferred font and bold keys.
        Handles all 'Key: Value' lines dynamically.
        """
        import html

        lines = text.strip().split('\n')
        formatted_lines = []

        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                formatted_lines.append(
                    f"<div><strong>{html.escape(key.strip())}:</strong> {html.escape(value.strip())}</div>")
            else:
                formatted_lines.append(f"<div>{html.escape(line.strip())}</div>")

        html_output = f"""
        <div style="font-family: Arial, sans-serif; font-size: 16px; color: #333; line-height: 1.6; padding: 8px 0;">
            {''.join(formatted_lines)}
        </div>
        """
        return html_output

    st.markdown("""
        <style>
        @keyframes pulse {
            0% {
                transform: scale(1);
                opacity: 1;
            }
            50% {
                transform: scale(1.05);
                opacity: 0.7;
            }
            100% {
                transform: scale(1);
                opacity: 1;
            }
        }

        .thinking-animation {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            animation: pulse 2s ease-in-out infinite;
            font-size: 18px;
            font-weight: 600;
            margin: 20px 0;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }

        .processing-dots {
            display: inline-block;
            width: 80px;
            text-align: left;
        }

        .processing-dots::after {
            content: '';
            animation: dots 1.5s steps(4, end) infinite;
        }

        @keyframes dots {
            0% { content: ''; }
            25% { content: '.'; }
            50% { content: '..'; }
            75% { content: '...'; }
            100% { content: ''; }
        }

        .thinking-icon {
            display: inline-block;
            animation: spin 2s linear infinite;
            margin-right: 10px;
        }

        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        </style>
        """, unsafe_allow_html=True)
    # Execute pending corrected query if exists (also moved outside loop)
    if "pending_corrected_sql" in st.session_state and st.session_state.pending_corrected_sql:
        pending = st.session_state.pending_corrected_sql
        st.session_state.pending_corrected_sql = None
        with st.spinner("Executing corrected query..."):
            try:
                fixed_sql = pending["sql"]
                original_prompt = pending["original_prompt"]
                result = query_snowflake(fixed_sql, st.session_state["user"])
                response_text = None  # No LLM SQL generation here, but keep for logging
                token_usage_first_call = 0
                # --- BEGIN: Use regular answer mechanism for result rendering ---
                import datetime
                result_to_save = result
                if isinstance(result, list) and len(result) > 100:
                    result_to_save = result[:100]
                if isinstance(result, dict) and "error" in result:
                    natural_response = result["error"]
                elif isinstance(result, list):
                    processed_result = []
                    has_datetime = False
                    if result and isinstance(result[0], dict):
                        for value in result[0].values():
                            if isinstance(value, (datetime.date, datetime.datetime)):
                                has_datetime = True
                                break
                    if has_datetime:
                        for item in result:
                            processed_item = {}
                            for key, value in item.items():
                                if isinstance(value, (datetime.date, datetime.datetime)):
                                    processed_item[key] = value.strftime('%Y-%m-%d')
                                else:
                                    processed_item[key] = value
                            processed_result.append(processed_item)
                        df = pd.DataFrame(processed_result)
                    else:
                        df = pd.DataFrame(result)
                    df = df.drop_duplicates()
                    num_rows = len(df)
                    has_null_content = False
                    if num_rows == 1:
                        if df.shape[1] == 1 and df.iloc[0, 0] is None:
                            has_null_content = True
                        elif isinstance(result, list) and len(result) == 1:
                            row = result[0]
                            if all(value is None for value in row.values()):
                                has_null_content = True
                    should_create_table = num_rows > 1 or (num_rows == 1 and df.shape[1] > 8)
                    if should_create_table:
                        df_idx = len(st.session_state.persistent_dfs)
                        st.session_state.persistent_dfs.append(df)
                        current_message_idx = len(
                            [m for m in st.session_state.chat_history if m["role"] == "assistant"]
                        )
                        st.session_state.chat_message_tables[current_message_idx] = df_idx
                        if num_rows > 200000:
                            natural_response = f"Query returned {num_rows:,} rows. Due to the large size of the result, only a download option is provided below. You can download the full dataset as a CSV file for viewing in your preferred spreadsheet application."
                        elif num_rows > 1:
                            natural_response = f"Query returned {num_rows:,} rows. The result is displayed below:"
                        else:
                            natural_response = "Here are the complete details in a structured format:"
                        token_usage_second_call = 0
                    elif num_rows == 0 or has_null_content:
                        natural_response = (
                            "No results found for the query.\n"
                            "- Double-check the spelling of table names, column names, and values.\n"
                            "- Verify that the data you're searching for exists in the database.\n"
                            "- Check for any case sensitivity issues."
                        )
                    else:
                        result_for_messages = result
                        # Use LLM for natural language response
                        ranking_criteria = ""
                        if any(keyword in original_prompt.lower() for keyword in
                               ['top', 'highest', 'most', 'maximum', 'best', 'largest', 'least', 'lowest', 'minimum']):
                            ranking_criteria = extract_ranking_criteria(fixed_sql)
                        instructions = {
                            "role": "user",
                            "content": f"""      
                                    User Question: {original_prompt}        
                                    Database Query Result: {result_for_messages}
                                    SQL Query Used: {fixed_sql}
                                    {f"Ranking Criteria: {ranking_criteria}" if ranking_criteria else ""}

                                    Instructions:       
                                    1. Directly use the database query result to answer the user's question.

                                    2. For ranking/top/maximum queries:
                                       - Always mention the criteria used for ranking
                                       - Use the \"Ranking Criteria\" provided above if available
                                       - Include the metric value if available in the result

                                    3. Format guidelines:
                                       - Use bullet points for better readability when there are many details
                                       - Bold important values like names, amounts, and dates
                                       - Keep monetary values properly formatted with commas

                                    4. Do not include raw SQL or JSON in the response

                                    5. Use chat history for context in follow-up questions

                                    Examples:
                                    - \"Top vendor by purchase orders\" → \"The top vendor is X with Y purchase orders\"
                                    - \"Highest spending project\" → \"Project X has the highest spending of $Y\"
                                    - \"Most active department\" → \"Department X is most active based on transaction count\"
                                    """
                        }
                        temp_messages = st.session_state.messages + [instructions]
                        natural_response, token_usage_second_call = get_groq_response_with_system(temp_messages)
                        st.session_state.total_tokens += token_usage_second_call
                        natural_response = clean_llm_response(natural_response)
                    # ----- Save Results & Display -----
                    save_query_result(
                        original_prompt,
                        natural_response,
                        result_to_save,
                        fixed_sql,
                        None,  # No LLM SQL generation here
                        tokens_first_call=0,
                        tokens_second_call=locals().get("token_usage_second_call", 0),
                        total_tokens_used=st.session_state.total_tokens
                    )

                    # Show final answer in the response container
                    st.session_state.messages.append({"role": "assistant", "content": natural_response})
                    st.session_state.chat_history.append({"role": "assistant", "content": natural_response})
                    save_after_exchange()
                    with st.chat_message("assistant"):
                        formatted_html = format_llm_response(natural_response)
                        st.markdown(formatted_html, unsafe_allow_html=True)
                        current_message_idx = len(
                            [m for m in st.session_state.chat_history if m["role"] == "assistant"]
                        ) - 1
                        if current_message_idx in st.session_state.chat_message_tables:
                            df_idx = st.session_state.chat_message_tables[current_message_idx]
                            if df_idx < len(st.session_state.persistent_dfs):
                                df = st.session_state.persistent_dfs[df_idx]
                                if not df.empty:
                                    display_table_with_size_handling(df, current_message_idx, df_idx)
                else:
                    natural_response = "No valid result returned."

                    # Save to query log
                    save_query_result(
                        original_prompt,
                        natural_response,
                        None,
                        fixed_sql,
                        None,
                        tokens_first_call=0,
                        tokens_second_call=0,
                        total_tokens_used=st.session_state.total_tokens,
                        error_message="No valid result returned"
                    )

                    st.session_state.messages.append({"role": "assistant", "content": natural_response})
                    st.session_state.chat_history.append({"role": "assistant", "content": natural_response})
                    save_after_exchange()
                    with st.chat_message("assistant"):
                        st.markdown(natural_response)
                # --- END: Use regular answer mechanism for result rendering ---
            except Exception as e:
                st.error(f"Error executing corrected query: {e}")

    def animated_progress_bar(container, message, progress_time=1.5):
        """Display an animated progress bar with a message."""
        with container:
            progress_bar = st.progress(0)
            status_text = st.empty()

            for i in range(101):
                progress_bar.progress(i)
                status_text.markdown(
                    f"<div style='color:#3366ff; font-weight:bold;'>{message}</div>",
                    unsafe_allow_html=True
                )
                time.sleep(progress_time / 100)

                # Pause briefly after finishing animation
            time.sleep(0.3)
            # Clear out the contents
            progress_bar.empty()
            status_text.empty()

    def clean_llm_response(response: str) -> str:

        """
        Cleans up LLM responses for consistent display:
        - Removes markdown formatting like *, _, `
        - Fixes spacing after commas
        - Normalizes multiple spaces
        """
        cleaned = re.sub(r'[*_`]', '', response)
        cleaned = re.sub(r',(?=\S)', ', ', cleaned)
        cleaned = re.sub(r'\s{2,}', ' ', cleaned)
        return cleaned.strip()

    def extract_ranking_criteria(sql_query: str) -> str:
        """
        Analyze SQL query to determine the ranking/sorting criteria
        Returns a human-readable description of the criteria
        """
        sql_upper = sql_query.upper()

        # Check ORDER BY clause
        order_by_match = re.search(r'ORDER\s+BY\s+([^;]+?)(?:DESC|ASC|LIMIT|$)', sql_upper, re.IGNORECASE)

        if order_by_match:
            order_clause = order_by_match.group(1).strip()

            # Common patterns
            if 'COUNT(' in order_clause:
                if 'DISTINCT' in order_clause:
                    # Extract what's being counted
                    count_match = re.search(r'COUNT\s*\(\s*DISTINCT\s+(\w+)', order_clause)
                    if count_match:
                        column = count_match.group(1).lower()
                        return f"based on the count of unique {column.replace('_', ' ')}s"
                else:
                    return "based on the total count"

            elif 'SUM(' in order_clause:
                sum_match = re.search(r'SUM\s*\(\s*(\w+)', order_clause)
                if sum_match:
                    column = sum_match.group(1).lower()
                    return f"based on the total {column.replace('_', ' ')}"

            elif 'MAX(' in order_clause:
                return "based on the maximum value"

            elif 'MIN(' in order_clause:
                return "based on the minimum value"

            elif 'AVG(' in order_clause:
                return "based on the average"

        # Check if there's a LIMIT without clear ordering (implies some kind of top/max query)
        if 'LIMIT' in sql_upper and 'GROUP BY' in sql_upper:
            return "based on the grouping and aggregation used"

        return ""

    def format_llm_response(text: str) -> str:
        """
        Formats LLM responses into clean HTML using preferred font and bold keys.
        Handles all 'Key: Value' lines dynamically.
        """
        import html

        lines = text.strip().split('\n')
        formatted_lines = []

        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                formatted_lines.append(
                    f"<div><strong>{html.escape(key.strip())}:</strong> {html.escape(value.strip())}</div>")
            else:
                formatted_lines.append(f"<div>{html.escape(line.strip())}</div>")

        html_output = f"""
        <div style="font-family: Arial, sans-serif; font-size: 16px; color: #333; line-height: 1.6; padding: 8px 0;">
            {''.join(formatted_lines)}
        </div>
        """
        return html_output

    st.markdown("""
        <style>
        @keyframes pulse {
            0% {
                transform: scale(1);
                opacity: 1;
            }
            50% {
                transform: scale(1.05);
                opacity: 0.7;
            }
            100% {
                transform: scale(1);
                opacity: 1;
            }
        }

        .thinking-animation {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            animation: pulse 2s ease-in-out infinite;
            font-size: 18px;
            font-weight: 600;
            margin: 20px 0;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }

        .processing-dots {
            display: inline-block;
            width: 80px;
            text-align: left;
        }

        .processing-dots::after {
            content: '';
            animation: dots 1.5s steps(4, end) infinite;
        }

        @keyframes dots {
            0% { content: ''; }
            25% { content: '.'; }
            50% { content: '..'; }
            75% { content: '...'; }
            100% { content: ''; }
        }

        .thinking-icon {
            display: inline-block;
            animation: spin 2s linear infinite;
            margin-right: 10px;
        }

        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        </style>
        """, unsafe_allow_html=True)

    # Replace the chat input section with this enhanced version:

    if prompt := st.chat_input("Type your business question here..."):
        # Create a placeholder for the initial loading animation
        initial_loading_placeholder = st.empty()

        # Check if we're waiting for error clarification
        # Check if we're waiting for error clarification
        if st.session_state.awaiting_error_clarification:
            # Don't process regular chat input when showing correction UI
            initial_loading_placeholder.empty()
            st.stop()

        # Show immediate loading animation
        with initial_loading_placeholder.container():
            st.markdown("""
                <div class="thinking-animation">
                    <span class="thinking-icon">🤔</span>
                    Processing your question<span class="processing-dots"></span>
                </div>
                """, unsafe_allow_html=True)

        # Check if we're waiting for a continuation choice
        if st.session_state.awaiting_continuation_choice and st.session_state.continuation_options:
            # User is responding to continuation question
            if prompt.strip() in ["1", "2"]:
                # Get the selected question
                selected_question = st.session_state.continuation_options[prompt.strip()]

                # Reset continuation state
                st.session_state.awaiting_continuation_choice = False
                st.session_state.continuation_options = None

                # Use the selected question as the actual prompt
                prompt = selected_question

                # Clear the loading animation and show info about the selection
                initial_loading_placeholder.empty()
                st.info(f"Using interpretation: {selected_question}")

                # IMPORTANT: Set a flag to skip continuation detection for this interaction
                skip_continuation_check = True
            else:
                # User typed something else, treat as new question
                st.session_state.awaiting_continuation_choice = False
                st.session_state.continuation_options = None
                skip_continuation_check = False
        else:
            skip_continuation_check = False

        # Store the original prompt for display purposes
        original_prompt = prompt

        # Check for continuation BEFORE applying corrections
        if st.session_state.messages and st.session_state.last_sql_query and not skip_continuation_check:
            # Update loading animation
            with initial_loading_placeholder.container():
                st.markdown("""
                    <div class="thinking-animation">
                        <span class="thinking-icon">🔍</span>
                        Checking for related questions<span class="processing-dots"></span>
                    </div>
                    """, unsafe_allow_html=True)

            continuation_result = check_and_handle_continuation(
                prompt,
                st.session_state.messages,
                schema_text,
                get_groq_response_with_system,
                st.session_state.last_sql_query
            )

            if continuation_result["is_continuation"]:
                # Clear loading animation
                initial_loading_placeholder.empty()

                # Show the original question in chat
                with st.chat_message("user"):
                    st.markdown(original_prompt)

                # Add to history
                st.session_state.messages.append({"role": "user", "content": original_prompt})
                st.session_state.chat_history.append({"role": "user", "content": original_prompt})

                # Show continuation options
                with st.chat_message("assistant"):
                    st.markdown(continuation_result["formatted_response"])

                # Save state for next interaction
                st.session_state.awaiting_continuation_choice = True
                st.session_state.continuation_options = continuation_result["options"]

                # Add assistant's response to history
                st.session_state.messages.append(
                    {"role": "assistant", "content": continuation_result["formatted_response"]})
                st.session_state.chat_history.append(
                    {"role": "assistant", "content": continuation_result["formatted_response"]})

                # Save the conversation
                save_after_exchange()

                # Stop here and wait for user's choice
                st.stop()

        # Update loading animation for synonym correction
        with initial_loading_placeholder.container():
            st.markdown("""
                <div class="thinking-animation">
                    <span class="thinking-icon">✨</span>
                    Optimizing your question<span class="processing-dots"></span>
                </div>
                """, unsafe_allow_html=True)

        # Apply both contextual and synonym corrections
        engine = get_snowflake_connection()
        corrected_prompt, correction_info = correct_user_question_enhanced(
            prompt,
            schema_text,
            engine,
            get_groq_response,
            conversation_history=st.session_state.messages
        )

        # Clear the initial loading animation
        initial_loading_placeholder.empty()

        # Determine which prompt to use
        final_prompt = corrected_prompt if correction_info.get('replacements') else original_prompt

        # Show the original question in the chat
        with st.chat_message("user"):
            st.markdown(original_prompt)

        # If corrections were made, show them with more detail
        if correction_info.get('replacements'):
            info_text = "**Query Correction Applied:**\n\n"
            info_text += f"Original: {original_prompt}\n\n"
            info_text += f"Corrected: {corrected_prompt}\n\n"

            # Show contextual replacements separately if any
            if correction_info.get('contextual_replacements'):
                info_text += "**Contextual replacements:**\n"
                for orig, repl in correction_info['contextual_replacements'].items():
                    info_text += f"- '{orig}' → '{repl}'\n"

            # Show synonym replacements if any
            if correction_info.get('synonym_replacements'):
                info_text += "\n**Synonym replacements:**\n"
                for orig, repl in correction_info['synonym_replacements'].items():
                    info_text += f"- '{orig}' → '{repl}'\n"

            st.info(info_text, icon="ℹ️")

        # IMPORTANT: Add the CORRECTED question to session state, not the original
        st.session_state.messages.append({"role": "user", "content": final_prompt})
        st.session_state.chat_history.append({"role": "user", "content": final_prompt})

        # Use the corrected prompt for ALL processing from here on
        prompt = final_prompt  # This ensures the corrected question is used everywhere below

        # Continue with the rest of your existing code...
        progress_container = st.container()
        response_container = st.container()
        final_message_placeholder = st.empty()

        sql_query = None
        response_text = None

        try:
            # 1. Analyzing phase
            animated_progress_bar(
                progress_container,
                "🔍 Analyzing your query...",
                progress_time=1.0
            )

            # 2. SQL generation update
            with progress_container:
                status_text = st.empty()
                status_text.markdown(
                    "<div style='color:#3366ff; font-weight:bold;'>💻 Generating SQL query...</div>",
                    unsafe_allow_html=True
                )

            response_text, token_usage_first_call = get_groq_response_with_clarifications(
                st.session_state.messages,
                st.session_state["user"],
                prompt,  # The current question
                schema_text
            )
            st.session_state.total_tokens += token_usage_first_call

            # Check if it's an error response
            if response_text.strip().startswith("ERROR:"):
                raise Exception(response_text.strip())

            # Clean the SQL query - remove markdown code blocks
            sql_query = response_text.strip()

            # Remove ```sql and ``` markers if present
            if sql_query.startswith("```sql"):
                sql_query = sql_query[6:]  # Remove ```sql
            if sql_query.startswith("```"):
                sql_query = sql_query[3:]  # Remove ```
            if sql_query.endswith("```"):
                sql_query = sql_query[:-3]  # Remove trailing ```

            # Final cleanup - strip any remaining whitespace
            sql_query = sql_query.strip()
            original_sql = sql_query
            sql_query = fix_generated_sql(sql_query, schema_text)
            st.session_state.last_sql_query = sql_query

            # 3. Executing query animation update
            with progress_container:
                status_text.markdown(
                    "<div style='color:#3366ff; font-weight:bold;'>⚡ Executing query on Snowflake...</div>",
                    unsafe_allow_html=True
                )

            # Execute the query directly
            result = query_snowflake(sql_query, st.session_state["user"])
            # 4. Processing results
            with progress_container:
                status_text.markdown(
                    "<div style='color:#3366ff; font-weight:bold;'>🔄 Processing results...</div>",
                    unsafe_allow_html=True
                )
            error_recovery = handle_ui_based_error_recovery(
                sql_query,
                result,
                None,  # No error message at this point
                schema_text,
                get_groq_response_with_system,
                st.session_state["user"]
            )

            if error_recovery["needs_clarification"]:
                # Clear any loading animations
                with progress_container:
                    if 'status_text' in locals():
                        status_text.empty()
                    progress_container.empty()

                if 'final_message_placeholder' in locals():
                    final_message_placeholder.empty()

                # Store the error recovery data
                st.session_state.awaiting_error_clarification = True
                st.session_state.error_clarification_data = {
                    "filter_info": error_recovery["filter_info"],  # Changed from problematic_filter
                    "original_sql": error_recovery["original_sql"],
                    "original_prompt": prompt
                }

                # Save to query log
                save_query_result(
                    prompt,
                    "Clarification needed",
                    None,
                    sql_query,
                    response_text,
                    tokens_first_call=token_usage_first_call,
                    tokens_second_call=0,
                    total_tokens_used=st.session_state.total_tokens,
                    error_message="Awaiting user clarification"
                )

                save_after_exchange()
                st.rerun()

                # ----- Handle Results -----
            result_to_save = result
            if isinstance(result, list) and len(result) > 100:
                # Take a sample of 100 rows for saving to Snowflake
                result_to_save = result[:100]
            if isinstance(result, dict) and "error" in result:
                natural_response = result["error"]
            elif isinstance(result, list):
                # Pre-process data (datetime conversions, etc.)
                processed_result = []
                has_datetime = False
                if result and isinstance(result[0], dict):
                    for value in result[0].values():
                        if isinstance(value, (datetime.date, datetime.datetime)):
                            has_datetime = True
                            break

                if has_datetime:
                    for item in result:
                        processed_item = {}
                        for key, value in item.items():
                            if isinstance(value, (datetime.date, datetime.datetime)):
                                processed_item[key] = value.strftime('%Y-%m-%d')
                            else:
                                processed_item[key] = value
                        processed_result.append(processed_item)
                    df = pd.DataFrame(processed_result)
                else:
                    df = pd.DataFrame(result)

                df = df.drop_duplicates()
                num_rows = len(df)
                # First check if results exist but are essentially empty/null
                has_null_content = False
                if num_rows == 1:
                    # Check if we have a single row with NULL values
                    if df.shape[1] == 1 and df.iloc[0, 0] is None:
                        has_null_content = True
                    # For dictionaries like [{'TOTAL_COST': None}]
                    elif isinstance(result, list) and len(result) == 1:
                        row = result[0]
                        if all(value is None for value in row.values()):
                            has_null_content = True

                should_create_table = num_rows > 1 or (num_rows == 1 and df.shape[1] > 8)

                if should_create_table:
                    df_idx = len(st.session_state.persistent_dfs)
                    st.session_state.persistent_dfs.append(df)
                    current_message_idx = len(
                        [m for m in st.session_state.chat_history if m["role"] == "assistant"]
                    )
                    st.session_state.chat_message_tables[current_message_idx] = df_idx

                    # Customize message based on what we're showing
                    if num_rows > 200000:
                        natural_response = f"Query returned {num_rows:,} rows. Due to the large size of the result, only a download option is provided below. You can download the full dataset as a CSV file for viewing in your preferred spreadsheet application."
                    elif num_rows > 1:
                        natural_response = f"Query returned {num_rows:,} rows. The result is displayed below:"
                    else:  # 1 row with many columns
                        natural_response = "Here are the complete details in a structured format:"

                    token_usage_second_call = 0
                elif num_rows == 0 or has_null_content:
                    with progress_container:
                        status_text.markdown(
                            "<div style='color:#3366ff; font-weight:bold;'>🔍 Checking for potential corrections...</div>",
                            unsafe_allow_html=True
                        )

                    correction_suggestions = enhance_query_correction(sql_query, extract_query_components)
                    if correction_suggestions and correction_suggestions.get('suggestions'):
                        natural_response = format_professional_suggestion(correction_suggestions)
                    else:
                        if has_null_content:
                            natural_response = (
                                "The query returned a result with only NULL values.\n"
                                "- Check if you're referencing the correct column names.\n"
                                "- Verify that the data you're searching for exists in the database.\n"
                                "- Ensure any aggregation functions or calculations are applied correctly."
                            )
                        else:
                            natural_response = (
                                "No results found for the query.\n"
                                "- Double-check the spelling of table names, column names, and values.\n"
                                "- Verify that the data you're searching for exists in the database.\n"
                                "- Check for any case sensitivity issues."
                            )
                else:
                    result_for_messages = result
                    with progress_container:
                        if 'status_text' in locals():
                            status_text.empty()
                        status_text = st.empty()
                        status_text.markdown(
                            "<div style='color:#3366ff; font-weight:bold;'>✍️ Generating human-friendly response...</div>",
                            unsafe_allow_html=True
                        )
                    # Extract ranking criteria if applicable
                    ranking_criteria = ""
                    if any(keyword in prompt.lower() for keyword in
                           ['top', 'highest', 'most', 'maximum', 'best', 'largest', 'least', 'lowest', 'minimum']):
                        ranking_criteria = extract_ranking_criteria(sql_query)

                    instructions = {
                        "role": "user",
                        "content": f"""      
                                User Question: {prompt}        
                                Database Query Result: {result_for_messages}
                                SQL Query Used: {sql_query}
                                {f"Ranking Criteria: {ranking_criteria}" if ranking_criteria else ""}

                                Instructions:       
                                1. Directly use the database query result to answer the user's question.

                                2. For ranking/top/maximum queries:
                                   - Always mention the criteria used for ranking
                                   - Use the "Ranking Criteria" provided above if available
                                   - Include the metric value if available in the result

                                3. Format guidelines:
                                   - Use bullet points for better readability when there are many details
                                   - Bold important values like names, amounts, and dates
                                   - Keep monetary values properly formatted with commas

                                4. Do not include raw SQL or JSON in the response

                                5. Use chat history for context in follow-up questions

                                Examples:
                                - "Top vendor by purchase orders" → "The top vendor is X with Y purchase orders"
                                - "Highest spending project" → "Project X has the highest spending of $Y"
                                - "Most active department" → "Department X is most active based on transaction count"
                                """
                    }
                    temp_messages = st.session_state.messages + [instructions]
                    natural_response, token_usage_second_call = get_groq_response_with_system(temp_messages)
                    st.session_state.total_tokens += token_usage_second_call
                    natural_response = clean_llm_response(natural_response)
                    with progress_container:
                        status_text.markdown(
                            "<div style='color:#3366ff; font-weight:bold;'>✨ Formatting results for display...</div>",
                            unsafe_allow_html=True
                        )
                        # Add a small delay so users can see this transition message
                        time.sleep(0.8)
            else:
                natural_response = "No valid result returned."

                # Clear everything in the progress container (removes bars plus text)
            with progress_container:
                # Clear any remaining status text
                if 'status_text' in locals():
                    status_text.empty()
                    # And clear the entire container just to be safe
                progress_container.empty()

                # Show final transition message just before displaying the answer
            final_message_placeholder.markdown(
                "<div style='color:#3366ff; font-weight:bold;'>🎬 Preparing your answer...</div>",
                unsafe_allow_html=True
            )

            # ----- Save Results & Display -----
            save_query_result(
                prompt,
                natural_response,
                result_to_save,
                sql_query,
                response_text,
                tokens_first_call=token_usage_first_call,
                tokens_second_call=locals().get("token_usage_second_call", None),
                total_tokens_used=st.session_state.total_tokens
            )

            st.session_state.messages.append({"role": "assistant", "content": natural_response})
            st.session_state.chat_history.append({"role": "assistant", "content": natural_response})

            save_after_exchange()

            # Clear the final transition message right before showing the answer
            final_message_placeholder.empty()

            # Show final answer in the response container
            with response_container:
                with st.chat_message("assistant"):
                    formatted_html = format_llm_response(natural_response)
                    st.markdown(formatted_html, unsafe_allow_html=True)

                    current_message_idx = len(
                        [m for m in st.session_state.chat_history if m["role"] == "assistant"]
                    ) - 1
                    if current_message_idx in st.session_state.chat_message_tables:
                        df_idx = st.session_state.chat_message_tables[current_message_idx]
                        if df_idx < len(st.session_state.persistent_dfs):
                            df = st.session_state.persistent_dfs[df_idx]
                            if not df.empty:
                                # Use our new function for consistent display handling
                                display_table_with_size_handling(df, current_message_idx, df_idx)

        except Exception as e:
            # If there's an error, clear the progress animation first
            with progress_container:
                # Clear any remaining status text
                if 'status_text' in locals():
                    status_text.empty()
                    # And clear the entire container just to be safe
                progress_container.empty()

                # Also clear the final message placeholder if it exists
            if 'final_message_placeholder' in locals():
                final_message_placeholder.empty()

            error_recovery = handle_ui_based_error_recovery(
                sql_query if 'sql_query' in locals() else None,
                {"error": str(e)},  # Pass error as dict
                str(e),
                schema_text,
                get_groq_response_with_system,
                st.session_state["user"]
            )

            if error_recovery["needs_clarification"]:
                # Store the error recovery data
                st.session_state.awaiting_error_clarification = True
                st.session_state.error_clarification_data = {
                    "filter_info": error_recovery["filter_info"],  # Changed from problematic_filter
                    "original_sql": error_recovery["original_sql"],
                    "original_prompt": prompt
                }

                # Show clarification message instead of error
                st.session_state.messages.append({"role": "assistant", "content": error_recovery["message"]})
                st.session_state.chat_history.append({"role": "assistant", "content": error_recovery["message"]})

                save_after_exchange()
                st.rerun()
            natural_response = f"Error: {str(e)}"
            save_query_result(
                prompt,
                None,
                None,
                sql_query if 'sql_query' in locals() else None,
                response_text if 'response_text' in locals() else str(e),
                error_message=str(e),
                tokens_first_call=locals().get("token_usage_first_call", None),
                total_tokens_used=st.session_state.total_tokens
            )
            st.session_state.messages.append({"role": "assistant", "content": natural_response})
            st.session_state.chat_history.append({"role": "assistant", "content": natural_response})
            with response_container:
                with st.chat_message("assistant"):
                    st.markdown(natural_response)


# ---------------------------------------------
# 9. Entry point
# ---------------------------------------------
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if st.session_state["authenticated"]:
    if needs_password_change(st.session_state["user"]):
        password_change_page()
    else:
        main_app()
else:
    login_page()