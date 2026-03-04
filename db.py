import os
import json
import pymysql

def get_db_connection():
    config_path = os.path.join(os.path.dirname(__file__), 'ipa.json')
    try:
        import re
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # Remove trailing commas from JSON
            content = re.sub(r',\s*}', '}', content)
            content = re.sub(r',\s*]', ']', content)
            config = json.loads(content)
        mysql_conf = config.get('MySqlConfig', {})
        return pymysql.connect(
            host=mysql_conf.get('Server', '127.0.0.1'),
            user=mysql_conf.get('Uid', 'root'),
            password=mysql_conf.get('Pwd', ''),
            database=mysql_conf.get('Database', 'scan_history'),
            cursorclass=pymysql.cursors.DictCursor
        )
    except Exception as e:
        print(f"Failed to connect to MySQL: {e}")
        return None

def execute_query(query, params=None):
    conn = get_db_connection()
    if not conn:
        return []
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            result = cursor.fetchall()
        return result
    except Exception as e:
        print(f"Error executing query: {e}")
        return []
    finally:
        conn.close()

def execute_update(query, params=None):
    conn = get_db_connection()
    if not conn:
        return False
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
        conn.commit()
        return True
    except Exception as e:
        print(f"Error executing update: {e}")
        return False
    finally:
        conn.close()

def get_latest_scans():
    query = """
    WITH Ranked AS (
        SELECT *, ROW_NUMBER() OVER(PARTITION BY ip ORDER BY scan_time DESC) as rn
        FROM ip_history
    )
    SELECT * FROM Ranked WHERE rn = 1;
    """
    return execute_query(query)
