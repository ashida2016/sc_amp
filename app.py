from flask import Flask, render_template, request, jsonify
from db import execute_query, get_latest_scans, execute_update

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

@app.route('/api/vendors')
def api_vendors():
    query = "SELECT DISTINCT vendor FROM ip_history WHERE vendor IS NOT NULL AND vendor != '' ORDER BY vendor"
    data = execute_query(query)
    return jsonify({"data": [r['vendor'] for r in data]})

@app.route('/api/device_types')
def api_device_types():
    query = "SELECT DISTINCT device_type FROM ip_history WHERE device_type IS NOT NULL AND device_type != '' ORDER BY device_type"
    data = execute_query(query)
    return jsonify({"data": [r['device_type'] for r in data]})

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
        SUM(CASE WHEN status = 'Active' THEN 1 ELSE 0 END) as active_ips,
        SUM(CASE WHEN status = 'Reserved' THEN 1 ELSE 0 END) as reserved_ips
    FROM Ranked 
    WHERE rn = 1 AND status IN ('Active', 'Reserved')
    GROUP BY subnet;
    """
    data = execute_query(query)
    for row in data:
        active_cnt = int(row['active_ips']) if row['active_ips'] else 0
        reserved_cnt = int(row['reserved_ips']) if row['reserved_ips'] else 0
        row['active_ips'] = active_cnt
        row['reserved_ips'] = reserved_cnt
        total = active_cnt + reserved_cnt
        row['utilization_pct'] = round((total / 254.0) * 100, 2)
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
           SUM(FIND_IN_SET('5432', ports) > 0) as pg_count,
           SUM(FIND_IN_SET('1433', ports) > 0) as mssql_count
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
    hours = request.args.get('hours')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    vendors = request.args.get('vendors')
    device_types = request.args.get('device_types')

    where_clause = "status = 'Active'"
    params = []

    if vendors:
        vendor_list = vendors.split(',')
        placeholders = ', '.join(['%s'] * len(vendor_list))
        where_clause += f" AND vendor IN ({placeholders})"
        params.extend(vendor_list)
        
    if device_types:
        device_type_list = device_types.split(',')
        placeholders = ', '.join(['%s'] * len(device_type_list))
        where_clause += f" AND device_type IN ({placeholders})"
        params.extend(device_type_list)

    group_by = "DATE(scan_time)"

    if start_date and end_date:
        where_clause += " AND DATE(scan_time) >= %s AND DATE(scan_time) <= %s"
        params.extend([start_date, end_date])
    elif hours:
        try:
            hours_int = int(hours)
            where_clause += " AND scan_time >= DATE_SUB(NOW(), INTERVAL %s HOUR)"
            params.append(hours_int)
            group_by = "DATE_FORMAT(scan_time, '%%Y-%%m-%%d %%H:%%i')"
        except ValueError:
            where_clause += " AND scan_time >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)"
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
    SELECT {group_by} as scan_date, COUNT(DISTINCT ip) as online_count
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
            if hasattr(row['scan_date'], 'strftime'):
                row['scan_date'] = row['scan_date'].strftime('%Y-%m-%d')
    return jsonify({"data": data})

@app.route('/vlan_info')
def vlan_info():
    return render_template('vlan_info.html')

@app.route('/api/vlan_info', methods=['GET', 'POST'])
def api_vlan_info():
    if request.method == 'GET':
        query = """
        WITH AllSubnets AS (
            SELECT DISTINCT SUBSTRING_INDEX(ip, '.', 3) COLLATE utf8mb4_unicode_ci as subnet FROM ip_history
            UNION
            SELECT subnet COLLATE utf8mb4_unicode_ci FROM vlan_info
        )
        SELECT a.subnet, COALESCE(v.comment, 'No comment') as comment
        FROM AllSubnets a
        LEFT JOIN vlan_info v ON a.subnet COLLATE utf8mb4_unicode_ci = v.subnet COLLATE utf8mb4_unicode_ci
        ORDER BY a.subnet
        """
        data = execute_query(query)
        return jsonify({"data": data})
    elif request.method == 'POST':
        try:
            req_data = request.json
            subnet = req_data.get('subnet')
            comment = req_data.get('comment')
            if subnet is not None and comment is not None:
                query = """
                INSERT INTO vlan_info (subnet, comment) VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE comment = VALUES(comment)
                """
                if execute_update(query, (subnet, comment)):
                    return jsonify({"status": "success"})
            return jsonify({"status": "error", "message": "Invalid request"}), 400
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/physical_info')
def physical_info():
    return render_template('physical_info.html')

@app.route('/api/physical_info', methods=['GET', 'POST', 'DELETE'])
def api_physical_info():
    if request.method == 'GET':
        query = "SELECT id, machine_name, management_ip, virtualization_type, purpose, comment FROM physical_machines ORDER BY id DESC"
        data = execute_query(query)
        return jsonify({"data": data})
    elif request.method == 'POST':
        try:
            req_data = request.json
            action = req_data.get('action')
            if action == 'add':
                query = """
                INSERT INTO physical_machines (machine_name, management_ip, virtualization_type, purpose, comment)
                VALUES (%s, %s, %s, %s, %s)
                """
                if execute_update(query, (
                    req_data.get('machine_name', 'New Machine'),
                    req_data.get('management_ip', ''),
                    req_data.get('virtualization_type', 'Esxi 7 Server'),
                    req_data.get('purpose', ''),
                    req_data.get('comment', '')
                )):
                    return jsonify({"status": "success"})
            elif action == 'update':
                query = """
                UPDATE physical_machines
                SET machine_name=%s, management_ip=%s, virtualization_type=%s, purpose=%s, comment=%s
                WHERE id=%s
                """
                if execute_update(query, (
                    req_data.get('machine_name', ''),
                    req_data.get('management_ip', ''),
                    req_data.get('virtualization_type', ''),
                    req_data.get('purpose', ''),
                    req_data.get('comment', ''),
                    req_data.get('id')
                )):
                    return jsonify({"status": "success"})
            return jsonify({"status": "error", "message": "Invalid/failed request"}), 400
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    elif request.method == 'DELETE':
        try:
            req_data = request.json
            query = "DELETE FROM physical_machines WHERE id=%s"
            if execute_update(query, (req_data.get('id'),)):
                return jsonify({"status": "success"})
            return jsonify({"status": "error", "message": "Delete failed"}), 400
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/ip_detail')
def ip_detail():
    return render_template('ip_detail.html')

@app.route('/api/ip_detail/init', methods=['GET'])
def api_ip_detail_init():
    try:
        # Fetch actual subnets from vlan_info or history
        subnets_query = "SELECT DISTINCT SUBSTRING_INDEX(ip, '.', 3) as subnet FROM ip_history ORDER BY subnet"
        subnets = [r['subnet'] for r in execute_query(subnets_query)]
        
        # Fetch device types
        dtype_query = "SELECT DISTINCT device_type FROM ip_history WHERE device_type IS NOT NULL AND device_type != '' ORDER BY device_type"
        device_types = [r['device_type'] for r in execute_query(dtype_query)]
        
        # Fetch physical machines
        pm_query = "SELECT id, machine_name FROM physical_machines ORDER BY machine_name"
        pms = execute_query(pm_query)
        
        return jsonify({"subnets": subnets, "device_types": device_types, "physical_machines": pms})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/ip_detail/search', methods=['GET'])
def api_ip_detail_search():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "IP is required"}), 400
        
    history_query = "SELECT * FROM ip_history WHERE ip = %s ORDER BY scan_time DESC LIMIT 1"
    history = execute_query(history_query, (ip,))
    
    extend_query = "SELECT * FROM ip_extend WHERE ip = %s"
    extend = execute_query(extend_query, (ip,))
    
    return jsonify({
        "history": history[0] if history else None,
        "extend": extend[0] if extend else None
    })

@app.route('/api/ip_detail/save', methods=['POST'])
def api_ip_detail_save():
    try:
        req_data = request.json
        ip = req_data.get('ip')
        if not ip:
            return jsonify({"status": "error", "message": "IP is missing"}), 400
        # Parse extend fields
        pm_id = req_data.get('pm_id')
        os_ver = req_data.get('os_ver')
        purpose = req_data.get('purpose')
        comment = req_data.get('comment')
        device_type = req_data.get('device_type', 'Any')
        hostname = req_data.get('hostname', 'TBD/待定')
        status = req_data.get('status', 'Reserved')
        
        pm_val = pm_id if pm_id != '' else None
        
        insert_ext = """
        INSERT INTO ip_extend (ip, pm_id, os_ver, purpose, comment, device_type, hostname, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE pm_id=VALUES(pm_id), os_ver=VALUES(os_ver), purpose=VALUES(purpose), comment=VALUES(comment), device_type=VALUES(device_type), hostname=VALUES(hostname), status=VALUES(status)
        """
        execute_update(insert_ext, (ip, pm_val, os_ver, purpose, comment, device_type, hostname, status))
        
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/report')
def report():
    return render_template('report.html')

@app.route('/api/report', methods=['GET'])
def api_report():
    query = """
    WITH LatestHistory AS (
        SELECT ip, mac, hostname as h_hostname, status as h_status, device_type as h_device_type, vendor, scan_time,
               SUBSTRING_INDEX(ip, '.', 3) COLLATE utf8mb4_unicode_ci as subnet
        FROM (
            SELECT *, ROW_NUMBER() OVER(PARTITION BY ip ORDER BY scan_time DESC) as rn
            FROM ip_history
        ) t WHERE rn = 1
    ),
    AllIPs AS (
        SELECT ip, subnet FROM LatestHistory
        UNION
        SELECT ip COLLATE utf8mb4_unicode_ci as ip, SUBSTRING_INDEX(ip, '.', 3) COLLATE utf8mb4_unicode_ci as subnet FROM ip_extend
    )
    SELECT 
        a.ip,
        a.subnet,
        h.mac, 
        h.h_hostname, 
        h.h_status, 
        h.h_device_type, 
        h.vendor, 
        h.scan_time,
        e.pm_id, 
        e.os_ver, 
        e.purpose, 
        e.comment, 
        e.device_type as e_device_type, 
        e.hostname as e_hostname, 
        e.status as e_status, 
        e.updated_time,
        p.machine_name
    FROM AllIPs a
    LEFT JOIN LatestHistory h ON a.ip = h.ip COLLATE utf8mb4_unicode_ci
    LEFT JOIN ip_extend e ON a.ip = e.ip COLLATE utf8mb4_unicode_ci
    LEFT JOIN physical_machines p ON e.pm_id = p.id
    ORDER BY INET_ATON(a.ip)
    """
    
    rows = execute_query(query)
    
    # Organize data by subnet
    report_data = {}
    subnets_list = set()
    for row in rows:
        subnet = row.get('subnet')
        if subnet not in report_data:
            report_data[subnet] = []
            subnets_list.add(subnet)
        report_data[subnet].append(row)
    
    # Sort subnets naturally using inet_aton similar trick or just sort by parts
    sorted_subnets = sorted(list(subnets_list), key=lambda s: [int(x) if x.isdigit() else 0 for x in s.split('.')])
    
    # Retrieve vlan comments
    vlan_rows = execute_query("SELECT subnet, comment FROM vlan_info")
    vlan_comments = {row['subnet']: row['comment'] for row in vlan_rows} if vlan_rows else {}
    
    return jsonify({
        "subnets": sorted_subnets,
        "data": report_data,
        "vlan_comments": vlan_comments
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
