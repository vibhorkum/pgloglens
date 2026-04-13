#!/usr/bin/env python3
"""Generate various PostgreSQL log scenarios for pgloglens testing.

This script connects to the test PostgreSQL container and generates
realistic log entries covering all major pgloglens detection capabilities.
"""

import os
import sys
import time
import threading
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

import psycopg2
from psycopg2 import sql, errors


DB_CONFIG = {
    "host": os.environ.get("PGHOST", "localhost"),
    "port": int(os.environ.get("PGPORT", "5433")),
    "dbname": os.environ.get("PGDATABASE", "testdb"),
    "user": os.environ.get("PGUSER", "testuser"),
    "password": os.environ.get("PGPASSWORD", "testpass"),
}


def get_connection(autocommit=False):
    """Create a new database connection."""
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = autocommit
    return conn


def generate_slow_queries():
    """Generate slow queries with varying durations."""
    print("[+] Generating slow queries...")
    conn = get_connection()
    cur = conn.cursor()

    # Queries with different complexities
    slow_queries = [
        # Aggregation queries
        """SELECT u.id, u.name, COUNT(o.id) as order_count, SUM(o.total) as total_spent
           FROM users u
           LEFT JOIN orders o ON o.user_id = u.id
           GROUP BY u.id, u.name
           ORDER BY total_spent DESC NULLS LAST""",

        # Cross join (intentionally slow)
        """SELECT COUNT(*) FROM users u1, users u2 WHERE u1.id < u2.id LIMIT 1""",

        # Subquery
        """SELECT * FROM users WHERE id IN (
               SELECT user_id FROM orders WHERE total > 100 GROUP BY user_id HAVING COUNT(*) > 2
           )""",

        # Large sort
        """SELECT * FROM large_data ORDER BY data, created_at DESC""",

        # Multiple joins
        """SELECT u.name, o.status, p.name as product_name
           FROM users u
           JOIN orders o ON o.user_id = u.id
           JOIN (SELECT DISTINCT user_id FROM orders WHERE total > 50) sub ON sub.user_id = u.id
           CROSS JOIN products p
           WHERE p.category_id = 1
           LIMIT 100""",
    ]

    for i, query in enumerate(slow_queries):
        try:
            cur.execute(query)
            cur.fetchall()
            print(f"  - Slow query {i+1} completed")
        except Exception as e:
            print(f"  - Slow query {i+1} error: {e}")

    conn.close()
    print("[+] Slow queries done")


def generate_errors():
    """Generate various error types."""
    print("[+] Generating errors...")
    conn = get_connection()
    cur = conn.cursor()

    error_scenarios = [
        # Duplicate key (23505)
        ("INSERT INTO users (id, email, name) VALUES (1, 'duplicate@test.com', 'Test')", "23505"),

        # Foreign key violation (23503)
        ("INSERT INTO orders (user_id, total) VALUES (999999, 100)", "23503"),

        # Syntax error (42601)
        ("SELEC * FROM users", "42601"),

        # Undefined table (42P01)
        ("SELECT * FROM nonexistent_table", "42P01"),

        # Division by zero (22012)
        ("SELECT 1/0", "22012"),

        # Invalid input (22P02)
        ("SELECT CAST('abc' AS INTEGER)", "22P02"),

        # Null constraint (23502)
        ("INSERT INTO users (email, name) VALUES (NULL, 'Test')", "23502"),
    ]

    for query, expected_code in error_scenarios:
        try:
            cur.execute(query)
            conn.commit()
        except psycopg2.Error as e:
            conn.rollback()
            print(f"  - Error {expected_code}: {e.pgcode}")

    conn.close()
    print("[+] Errors done")


def generate_lock_contention():
    """Generate lock wait events and potential deadlocks."""
    print("[+] Generating lock contention...")

    def worker_a():
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute("BEGIN")
            cur.execute("UPDATE inventory SET quantity = quantity + 1 WHERE id = 1")
            time.sleep(0.5)
            cur.execute("UPDATE inventory SET quantity = quantity + 1 WHERE id = 2")
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"  - Worker A: {e}")
        finally:
            conn.close()

    def worker_b():
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute("BEGIN")
            cur.execute("UPDATE inventory SET quantity = quantity + 1 WHERE id = 2")
            time.sleep(0.5)
            cur.execute("UPDATE inventory SET quantity = quantity + 1 WHERE id = 1")
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"  - Worker B: {e}")
        finally:
            conn.close()

    # Run concurrent updates to create lock waits
    threads = [
        threading.Thread(target=worker_a),
        threading.Thread(target=worker_b),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print("[+] Lock contention done")


def generate_temp_files():
    """Generate queries that create temp files."""
    print("[+] Generating temp file scenarios...")
    conn = get_connection()
    cur = conn.cursor()

    # Queries that should create temp files due to sorting/hashing
    temp_queries = [
        """SELECT * FROM large_data ORDER BY data, id""",
        """SELECT d1.data, d2.data FROM large_data d1
           CROSS JOIN large_data d2
           WHERE d1.id < 10 AND d2.id < 10
           ORDER BY d1.data, d2.data""",
        """SELECT DISTINCT data FROM large_data ORDER BY data""",
    ]

    for i, query in enumerate(temp_queries):
        try:
            cur.execute(query)
            cur.fetchall()
            print(f"  - Temp file query {i+1} completed")
        except Exception as e:
            print(f"  - Temp file query {i+1} error: {e}")

    conn.close()
    print("[+] Temp files done")


def generate_connections():
    """Generate connection events."""
    print("[+] Generating connection events...")

    connections = []
    for i in range(10):
        try:
            conn = get_connection()
            connections.append(conn)
            cur = conn.cursor()
            cur.execute("SELECT 1")
        except Exception as e:
            print(f"  - Connection {i+1} error: {e}")

    # Close connections
    time.sleep(0.5)
    for conn in connections:
        conn.close()

    print("[+] Connections done")


def generate_auth_failures():
    """Generate authentication failure events."""
    print("[+] Generating auth failures...")

    bad_credentials = [
        {"user": "baduser", "password": "wrongpass"},
        {"user": "hacker", "password": "password123"},
        {"user": "admin", "password": "admin"},
        {"user": "root", "password": "root"},
    ]

    for creds in bad_credentials:
        try:
            config = DB_CONFIG.copy()
            config["user"] = creds["user"]
            config["password"] = creds["password"]
            conn = psycopg2.connect(**config)
            conn.close()
        except psycopg2.OperationalError as e:
            print(f"  - Auth failure for {creds['user']}: (expected)")

    print("[+] Auth failures done")


def generate_checkpoints():
    """Generate checkpoint events by writing data."""
    print("[+] Generating checkpoint activity...")
    conn = get_connection()
    cur = conn.cursor()

    # Write enough data to trigger checkpoints
    for i in range(5):
        cur.execute("""
            INSERT INTO large_data (data)
            SELECT repeat('y', 10000) FROM generate_series(1, 100)
        """)
        conn.commit()
        time.sleep(1)

    # Force a checkpoint
    cur.execute("CHECKPOINT")
    conn.commit()

    conn.close()
    print("[+] Checkpoint activity done")


def generate_autovacuum():
    """Generate autovacuum activity."""
    print("[+] Generating autovacuum activity...")
    conn = get_connection()
    cur = conn.cursor()

    # Create and delete data to trigger autovacuum
    for i in range(3):
        cur.execute("""
            INSERT INTO orders (user_id, status, total)
            SELECT
                (random() * 999 + 1)::INTEGER,
                'temp',
                (random() * 100)::DECIMAL(10,2)
            FROM generate_series(1, 1000)
        """)
        conn.commit()

        cur.execute("DELETE FROM orders WHERE status = 'temp'")
        conn.commit()

        time.sleep(2)

    conn.close()
    print("[+] Autovacuum activity done")


def generate_mixed_workload():
    """Generate a mixed workload with concurrent operations."""
    print("[+] Generating mixed workload...")

    def worker(worker_id):
        conn = get_connection()
        cur = conn.cursor()

        operations = [
            "SELECT * FROM users WHERE id = %s",
            "SELECT * FROM orders WHERE user_id = %s LIMIT 10",
            "UPDATE inventory SET quantity = quantity + 1 WHERE product_id = %s",
            "SELECT COUNT(*) FROM products WHERE category_id = %s",
        ]

        for _ in range(10):
            op = random.choice(operations)
            param = random.randint(1, 100)
            try:
                cur.execute(op, (param,))
                if op.startswith("SELECT"):
                    cur.fetchall()
                conn.commit()
            except Exception:
                conn.rollback()

        conn.close()
        return worker_id

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(worker, i) for i in range(10)]
        for future in as_completed(futures):
            future.result()

    print("[+] Mixed workload done")


def main():
    """Run all log generation scenarios."""
    print("=" * 60)
    print("pgloglens Test Log Generator")
    print("=" * 60)

    # Wait for database to be ready
    print("\n[*] Waiting for database...")
    for attempt in range(30):
        try:
            conn = get_connection()
            conn.close()
            print("[*] Database is ready!")
            break
        except psycopg2.OperationalError:
            time.sleep(1)
    else:
        print("[!] Could not connect to database")
        sys.exit(1)

    print("\n[*] Starting log generation scenarios...\n")

    # Run all scenarios
    generate_connections()
    print()
    generate_auth_failures()
    print()
    generate_slow_queries()
    print()
    generate_errors()
    print()
    generate_lock_contention()
    print()
    generate_temp_files()
    print()
    generate_checkpoints()
    print()
    generate_autovacuum()
    print()
    generate_mixed_workload()

    print("\n" + "=" * 60)
    print("Log generation complete!")
    print("=" * 60)

    # Give PostgreSQL time to flush logs
    print("\n[*] Waiting for logs to flush...")
    time.sleep(3)


if __name__ == "__main__":
    main()
