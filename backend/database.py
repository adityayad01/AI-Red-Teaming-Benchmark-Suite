import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "results.db"


def get_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create all tables if they don't exist."""
    conn = get_connection()
    cursor = conn.cursor()

    # Sessions table - one row per benchmark run
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            model_name TEXT NOT NULL,
            attack_categories TEXT NOT NULL,
            total_prompts INTEGER DEFAULT 0,
            safe_count INTEGER DEFAULT 0,
            unsafe_count INTEGER DEFAULT 0,
            ambiguous_count INTEGER DEFAULT 0,
            overall_score REAL DEFAULT 0.0,
            status TEXT DEFAULT 'running',
            created_at TEXT NOT NULL,
            completed_at TEXT
        )
    """)

    # Results table - one row per prompt tested
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            attack_id TEXT NOT NULL,
            attack_category TEXT NOT NULL,
            attack_description TEXT NOT NULL,
            prompt TEXT NOT NULL,
            response TEXT NOT NULL,
            verdict TEXT NOT NULL,
            confidence REAL DEFAULT 0.0,
            reasoning TEXT,
            response_time_ms INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        )
    """)

    # Category scores table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS category_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            category TEXT NOT NULL,
            total INTEGER DEFAULT 0,
            safe_count INTEGER DEFAULT 0,
            unsafe_count INTEGER DEFAULT 0,
            ambiguous_count INTEGER DEFAULT 0,
            vulnerability_score REAL DEFAULT 0.0,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        )
    """)

    conn.commit()
    conn.close()
    print(f"✅ Database initialized at {DB_PATH}")


def create_session(session_id: str, model_name: str, attack_categories: list) -> bool:
    try:
        conn = get_connection()
        conn.execute("""
            INSERT INTO sessions (session_id, model_name, attack_categories, created_at)
            VALUES (?, ?, ?, ?)
        """, (session_id, model_name, json.dumps(attack_categories), datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error creating session: {e}")
        return False


def save_result(session_id: str, attack_id: str, category: str, description: str,
                prompt: str, response: str, verdict: str, confidence: float,
                reasoning: str, response_time_ms: int) -> bool:
    try:
        conn = get_connection()
        conn.execute("""
            INSERT INTO results 
            (session_id, attack_id, attack_category, attack_description, prompt, response, 
             verdict, confidence, reasoning, response_time_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_id, attack_id, category, description, prompt, response,
              verdict, confidence, reasoning, response_time_ms, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error saving result: {e}")
        return False


def update_session_stats(session_id: str, safe: int, unsafe: int, ambiguous: int,
                         overall_score: float, status: str = "completed") -> bool:
    try:
        conn = get_connection()
        conn.execute("""
            UPDATE sessions 
            SET safe_count=?, unsafe_count=?, ambiguous_count=?,
                total_prompts=?, overall_score=?, status=?, completed_at=?
            WHERE session_id=?
        """, (safe, unsafe, ambiguous, safe + unsafe + ambiguous,
              overall_score, status, datetime.now().isoformat(), session_id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error updating session: {e}")
        return False


def save_category_scores(session_id: str, scores: dict) -> bool:
    try:
        conn = get_connection()
        for category, data in scores.items():
            conn.execute("""
                INSERT INTO category_scores 
                (session_id, category, total, safe_count, unsafe_count, ambiguous_count, vulnerability_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (session_id, category, data["total"], data["safe"],
                  data["unsafe"], data["ambiguous"], data["vulnerability_score"]))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error saving category scores: {e}")
        return False


def get_all_sessions() -> list:
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM sessions ORDER BY created_at DESC
    """).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_session_results(session_id: str) -> list:
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM results WHERE session_id=? ORDER BY attack_category, attack_id
    """, (session_id,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_session_category_scores(session_id: str) -> list:
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM category_scores WHERE session_id=?
    """, (session_id,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_session_by_id(session_id: str) -> dict:
    conn = get_connection()
    row = conn.execute("""
        SELECT * FROM sessions WHERE session_id=?
    """, (session_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


# Initialize DB on import
init_db()