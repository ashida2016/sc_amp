from db import execute_update

sql = """
CREATE OR REPLACE VIEW vw_ip_status AS
WITH LatestHistory AS (
    SELECT ip, status as h_status,
           SUBSTRING_INDEX(ip, '.', 3) COLLATE utf8mb4_unicode_ci as subnet
    FROM (
        SELECT *, ROW_NUMBER() OVER(PARTITION BY ip ORDER BY scan_time DESC) as rn
        FROM ip_history
    ) t WHERE rn = 1
),
AllIPs AS (
    SELECT ip COLLATE utf8mb4_unicode_ci as ip, subnet FROM LatestHistory
    UNION
    SELECT ip COLLATE utf8mb4_unicode_ci as ip, SUBSTRING_INDEX(ip, '.', 3) COLLATE utf8mb4_unicode_ci as subnet FROM ip_extend
)
SELECT 
    a.ip,
    a.subnet,
    COALESCE(NULLIF(h.h_status, ''), NULLIF(e.status, ''), 'Unknown') AS final_status
FROM AllIPs a
LEFT JOIN LatestHistory h ON a.ip = h.ip
LEFT JOIN ip_extend e ON a.ip = e.ip COLLATE utf8mb4_unicode_ci;
"""
execute_update(sql)
print("View created successfully")
