# sc_amp
Scanner Asset Management Platform  资产管理看板

在 MySQL 的数据库内，存储着定期/不定期对于局域网内资产扫描的数据。
扫描数据基于 ip 存储，数据库表结构如下：
CREATE TABLE IF NOT EXISTS ip_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '自增主键',
    ip VARCHAR(15) NOT NULL COMMENT 'IP地址',
    hostname VARCHAR(255) DEFAULT '' COMMENT '主机名',
    mac VARCHAR(17) DEFAULT '00:00:00:00:00:00' COMMENT '物理地址',
    vendor TEXT COMMENT '厂商列表(逗号分隔)',
    status VARCHAR(10) DEFAULT 'Inactive' COMMENT '活动状态',
    source VARCHAR(50) DEFAULT 'None' COMMENT '探测来源',
    device_type VARCHAR(50) DEFAULT 'Unknown' COMMENT '分析出的设备类型',
    ports TEXT COMMENT '开放端口列表(逗号分隔)',
    scan_time DATETIME NOT NULL COMMENT '扫描完成时间',
    -- 索引优化：用于查询特定 IP 的历史记录
    INDEX idx_ip_time (ip, scan_time),
    -- 索引优化：用于查询特定时间段的活跃设备
    INDEX idx_scan_time (scan_time)
) ENGINE=InnoDB COMMENT='ipa工具扫描履历全量表';

基于此数据创建一个了名为 sc_amp 的项目，希望完成如下功能：
1. 可以展示每个 ip 的被使用详细情况，展示 IP 在不同时间内被不同设备占用的履历
2. 资产指纹维度 (Asset Fingerprinting)，这是最基础的维度，用于回答“内网里到底有什么”的问题。
	2.1 厂商分布 (Vendor Stats)：
	分析点： 统计 Hikvision, Huawei, Apple, VMware 等厂商的占比。
	用途： 评估品牌依赖度。例如，如果发现大量未知厂商或山寨厂商设备，可能存在供应链安全风险。
	2.2 设备类型占比 (Device Type Distribution)：
	分析点： 将设备归类为 Web Server, Database, IP Camera, PC, Network Infrastructure。
	用途： 了解资产构成。如果监控类设备（Camera）占比异常升高，需关注带宽压力。
3. 空间与生命周期维度 (Spatial & Lifecycle)
	3.1 利用 scan_time 和 ip 字段，分析网络资源的使用效率。
	IP 地址利用率 (IP Utilization)：
	分析点： 在特定的子网（如 192.168.1.0/24）中，已用 IP 与空闲 IP 的比例。
	用途： 扩容决策。当利用率超过 80% 时，提醒网络管理员申请新的网段。
	3.2 IP 变化频率 (IP Churn Rate)：
	分析点： 统计同一个 IP 在一段时间内关联过多少个不同的 MAC 地址。
	用途： 识别动态环境。 变化频繁的 IP 通常是 DHCP 办公区；长期不变的则是服务器区或固定 IP 资产。
4. 合规性与基线维度 (Compliance & Baseline)
	4.1 将扫描结果与预期状态进行比对。
	非标准端口暴露 (Shadow IT Detection)：
	分析点： 统计哪些 IP 开放了不该开放的端口（例如：办公电脑开放了 3306 数据库端口，或摄像头开放了 22 SSH 端口）。
	用途： 发现违规配置。通过 ProtocolValidator 的深度探测，可以过滤掉防火墙虚假响应，直击真实的违规服务。
	4.2 “僵尸”资产识别 (Zombie Assets)：
	分析点： 筛选出 status='Active' 但 hostname 为空、mac 地址为"00:00:00:00:00:00"，且没有开放任何常用端口的设备。
	用途： 清理哑终端。这些设备可能是长期无人维护的旧路由器或打印机。
5. 风险与弱点维度 (Risk & Vulnerability)
	5.1 结合端口深度测试结果，评估攻击面。
	敏感服务分布：
	分析点： 全网范围内 RDP (3389)、VNC、Telnet (23) 等高危管理入口的数量。
	用途： 专项加固。比如要求所有的 RDP 必须下线，改用 VPN。
	5.2 数据库暴露面：
	分析点： 统计 MySQL, Oracle, Redis 等数据库在不同网段的分布情况。
	用途： 数据安全合规。确保生产环境的数据库不会出现在测试网段中。
6. 时间序列维度 (Time Series Analysis)
	6.1 利用 scan_time 观察趋势。
	在线设备趋势图：
	分析点： 以小时或天为单位，展示内网在线设备的总数波动。
	用途： 异常行为监测。例如，凌晨 3 点在线设备数突然激增，可能预示着蠕虫病毒爆发或大规模自动化攻击。

主要技术栈：
1. Flask构建网站后台
2. bootstrap 5.3.8 构建网页前端，而且网页内表格均使用 DataTables 技术实现
3. 所有图表展示均使用 ECharts 6.0 实现

UI 设计要点
1. 使用二级菜单展示各功能

配置文件
1. 关于数据库连接的配置，存放在名为 ipa.json 文件中，示例如下
{
    "MySqlConfig": {
		"Server" : "192.168.1.50",
		"Database" :"scan_history",
		"Uid" : "scaner",
		"Pwd" : "ipaRecord2026^",
    }
}
