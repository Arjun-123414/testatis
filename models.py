# models.py
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime,timezone
from sqlalchemy import Boolean

# Define the SQLite database URL
DATABASE_URL = "sqlite:///log.db"

# Create the SQLAlchemy engine
engine = create_engine(DATABASE_URL)

# Create a configured "Session" class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a DeclarativeMeta instance
Base = declarative_base()

from sqlalchemy import Boolean  # Import Boolean for the new column

class QueryResult(Base):
    __tablename__ = "query_result"

    id = Column(Integer, primary_key=True, index=True)
    query = Column(String, nullable=False)
    answer = Column(Text, nullable=True)
    sfresult = Column(Text, nullable=True)
    sqlquery = Column(Text, nullable=True)
    raw_response = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    tokens_first_call = Column(Integer, nullable=True)  # Tokens used in the first call
    tokens_second_call = Column(Integer, nullable=True)  # Tokens used in the second call
    total_tokens_used = Column(Integer, nullable=True)  # Total tokens used
    created_at = Column(DateTime, default=datetime.utcnow)  # Timestamp for when the query was executed
    synced_to_snowflake = Column(Boolean, default=False)  # New column to track sync status


class ChatHistory(Base):
    __tablename__ = "chat_history"

    id = Column(Integer, primary_key=True, index=True)
    user = Column(String, index=True)
    title = Column(String)
    timestamp = Column(DateTime(timezone=True))
    messages = Column(String)  # JSON string
    persistent_df_paths = Column(String)  # JSON string of file paths (will not be used anymore)
    persistent_df_mappings = Column(String)  # JSON string mapping assistant messages to DFs
    small_tables_data = Column(String, nullable=True)  # NEW: JSON string for small tables data



# Create the database tables
Base.metadata.create_all(bind=engine)
