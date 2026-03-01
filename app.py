from flask import Flask, render_template, request, jsonify
from db import execute_query, get_latest_scans

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/ip_history')
def ip_history():
    return render_template('ip_history.html')

@app.route('/api/ip_history')
def api_ip_history():
    ip = request.args.get('ip')
    if ip:
        query = "SELECT * FROM ip_history WHERE ip = %s ORDER BY scan_time DESC"
        data = execute_query(query, (ip,))
    else:
        query = """
        WITH Ranked AS (
            SELECT *, ROW_NUMBER() OVER(PARTITION BY ip ORDER BY scan_time DESC) as rn
            FROM ip_history
        )
        SELECT ip, hostname, mac, vendor, status, device_type, scan_time 
        FROM Ranked WHERE rn = 1;
        """
        data = execute_query(query)
    
    # Format datetimes
    for row in data:
        if 'scan_time' in row and row['scan_time']:
            row['scan_time'] = row['scan_time'].strftime('%Y-%m-%d %H:%M:%S')
            
    return jsonify({"data": data})

@app.route('/api/ip_history_detail')
def api_ip_history_detail():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"data": []})
    query = "SELECT * FROM ip_history WHERE ip = %s ORDER BY scan_time DESC"
    data = execute_query(query, (ip,))
    for row in data:
        if 'scan_time' in row and row['scan_time']:
            row['scan_time'] = row['scan_time'].strftime('%Y-%m-%d %H:%M:%S')
    return jsonify({"data": data})

@app.route('/fingerprint')
def fingerprint():
    return render_template('fingerprint.html')

@app.route('/api/fingerprint/vendor')
def api_fingerprint_vendor():
    query = """
    WITH Ranked AS (
        SELECT *, ROW_NUMBER() OVER(PARTITION BY ip ORDER BY scan_time DESC) as rn
        FROM ip_history
    )
    SELECT vendor, COUNT(DISTINCT ip) as count 
    FROM Ranked 
    WHERE rn = 1 AND vendor IS NOT NULL AND vendor != ''
    GROUP BY vendor 
    ORDER BY count DESC
    LIMIT 20;
    """
    data = execute_query(query)
    return jsonify({"data": data})

@app.route('/api/fingerprint/device_type')
def api_fingerprint_device_type():
    query = """
    WITH Ranked AS (
        SELECT *, ROW_NUMBER() OVER(PARTITION BY ip ORDER BY scan_time DESC) as rn
        FROM ip_history
    )
    SELECT device_type, COUNT(DISTINCT ip) as count 
    FROM Ranked 
    WHERE rn = 1 AND device_type IS NOT NULL AND device_type != ''
    GROUP BY device_type 
    ORDER BY count DESC;
    """
    data = execute_query(query)
    return jsonify({"data": data})

@app.route('/lifecycle')
def lifecycle():
    return render_template('lifecycle.html')

@app.route('/api/lifecycle/utilization')
def api_lifecycle_utilization():
    query = """
    WITH Ranked AS (
        SELECT *, ROW_NUMBER() OVER(PARTITION BY ip ORDER BY scan_time DESC) as rn
        FROM ip_history
    )
    SELECT 
        SUBSTRING_INDEX(ip, '.', 3) as subnet,
        COUNT(DISTINCT ip) as active_ips
    FROM Ranked 
    WHERE rn = 1 AND status = 'Active'
    GROUP BY subnet;
    """
    data = execute_query(query)
    for row in data:
        row['utilization_pct'] = round((row['active_ips'] / 254.0) * 100, 2)
    return jsonify({"data": data})

@app.route('/api/lifecycle/churn')
def api_lifecycle_churn():
    query = """
    SELECT ip, COUNT(DISTINCT mac) as mac_count 
    FROM ip_history 
    GROUP BY ip 
    HAVING mac_count > 1 
    ORDER BY mac_count DESC
    LIMIT 100;
    """
    data = execute_query(query)
    return jsonify({"data": data})

@app.route('/compliance')
def compliance():
    return render_template('compliance.html')

@app.route('/api/compliance/shadow_it')
def api_compliance_shadow_it():
    query = """
    WITH Ranked AS (
        SELECT *, ROW_NUMBER() OVER(PARTITION BY ip ORDER BY scan_time DESC) as rn
        FROM ip_history
    )
    SELECT ip, hostname, device_type, ports, scan_time
    FROM Ranked 
    WHERE rn = 1 
      AND (
          (ports LIKE '%3306%' AND device_type != 'Database')
       OR (ports LIKE '%22%' AND device_type = 'IP Camera')
       OR (ports LIKE '%3389%' AND device_type != 'PC' AND device_type != 'Server')
      );
    """
    data = execute_query(query)
    for row in data:
        if 'scan_time' in row and row['scan_time']:
            row['scan_time'] = row['scan_time'].strftime('%Y-%m-%d %H:%M:%S')
    return jsonify({"data": data})

@app.route('/api/compliance/zombies')
def api_compliance_zombies():
    query = """
    WITH Ranked AS (
        SELECT *, ROW_NUMBER() OVER(PARTITION BY ip ORDER BY scan_time DESC) as rn
        FROM ip_history
    )
    SELECT ip, hostname, mac, vendor, scan_time
    FROM Ranked 
    WHERE rn = 1 
      AND (mac = '00:00:00:00:00:00' OR status = 'Inactive');
    """
    data = execute_query(query)
    for row in data:
        if 'scan_time' in row and row['scan_time']:
            row['scan_time'] = row['scan_time'].strftime('%Y-%m-%d %H:%M:%S')
    return jsonify({"data": data})

@app.route('/risk')
def risk():
    return render_template('risk.html')

@app.route('/api/risk/sensitive')
def api_risk_sensitive():
    query = """
    WITH Ranked AS (
        SELECT *, ROW_NUMBER() OVER(PARTITION BY ip ORDER BY scan_time DESC) as rn
        FROM ip_history
    )
    SELECT 'RDP (3389)' as service, COUNT(*) as count FROM Ranked WHERE rn = 1 AND FIND_IN_SET('3389', ports) > 0 AND status='Active'
    UNION
    SELECT 'VNC (5900)' as service, COUNT(*) as count FROM Ranked WHERE rn = 1 AND FIND_IN_SET('5900', ports) > 0 AND status='Active'
    UNION
    SELECT 'Telnet (23)' as service, COUNT(*) as count FROM Ranked WHERE rn = 1 AND FIND_IN_SET('23', ports) > 0 AND status='Active'
    UNION
    SELECT 'SSH (22)' as service, COUNT(*) as count FROM Ranked WHERE rn = 1 AND FIND_IN_SET('22', ports) > 0 AND status='Active';
    """
    data = execute_query(query)
    return jsonify({"data": data})

@app.route('/api/risk/database')
def api_risk_database():
    query = """
    WITH Ranked AS (
        SELECT *, ROW_NUMBER() OVER(PARTITION BY ip ORDER BY scan_time DESC) as rn
        FROM ip_history
    )
    SELECT SUBSTRING_INDEX(ip, '.', 3) as subnet,
           SUM(FIND_IN_SET('3306', ports) > 0) as mysql_count,
           SUM(FIND_IN_SET('1521', ports) > 0) as oracle_count,
           SUM(FIND_IN_SET('6379', ports) > 0) as redis_count,
           SUM(FIND_IN_SET('5432', ports) > 0) as pg_count
    FROM Ranked
    WHERE rn = 1 AND status='Active'
    GROUP BY subnet;
    """
    data = execute_query(query)
    # Convert Decimals to int
    for row in data:
        for k, v in row.items():
            if isinstance(v, type(1.0)) or k.endswith('_count'): # Decimal is returned
                row[k] = int(v) if v else 0
    return jsonify({"data": data})

@app.route('/trend')
def trend():
    return render_template('trend.html')

@app.route('/api/trend/online')
def api_trend_online():
    days = request.args.get('days')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    where_clause = "status = 'Active'"
    params = []

    if start_date and end_date:
        where_clause += " AND DATE(scan_time) >= %s AND DATE(scan_time) <= %s"
        params.extend([start_date, end_date])
    elif days:
        try:
            days_int = int(days)
            where_clause += " AND scan_time >= DATE_SUB(CURDATE(), INTERVAL %s DAY)"
            params.append(days_int)
        except ValueError:
            where_clause += " AND scan_time >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)"
    else:
        where_clause += " AND scan_time >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)"

    query = f"""
    SELECT DATE(scan_time) as scan_date, COUNT(DISTINCT ip) as online_count
    FROM ip_history
    WHERE {where_clause}
    GROUP BY scan_date
    ORDER BY scan_date
    """
    
    if params:
        data = execute_query(query, tuple(params))
    else:
        data = execute_query(query)

    for row in data:
        if 'scan_date' in row and row['scan_date']:
            row['scan_date'] = row['scan_date'].strftime('%Y-%m-%d')
    return jsonify({"data": data})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
