-- 1) 创建数据库（如果不存在则新建）
CREATE DATABASE IF NOT EXISTS scan_history CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE scan_history;

-- 2) 创建vlan_info表
CREATE TABLE IF NOT EXISTS `vlan_info` (
  `subnet` varchar(50) NOT NULL COMMENT 'Network Subnet (e.g., 192.168.1.x)',
  `comment` varchar(255) DEFAULT 'No comment' COMMENT 'VLAN Comment/Description',
  PRIMARY KEY (`subnet`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3) Create manager account
CREATE USER IF NOT EXISTS 'manager'@'%' IDENTIFIED BY 'ampManager2026^';
GRANT SELECT, INSERT, UPDATE, DELETE ON `scan_history`.* TO 'manager'@'%';
FLUSH PRIVILEGES;

-- 4) Create physical_machines table
CREATE TABLE IF NOT EXISTS `physical_machines` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `machine_name` varchar(100) NOT NULL COMMENT '物理机名称',
  `management_ip` varchar(50) NOT NULL COMMENT '管理 IP',
  `virtualization_type` varchar(50) NOT NULL COMMENT '虚拟化机制',
  `purpose` varchar(255) DEFAULT '' COMMENT '用途说明',
  `comment` varchar(255) DEFAULT '' COMMENT '备注',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5) Create ip_extend table
CREATE TABLE IF NOT EXISTS `ip_extend` (
  `ip` varchar(15) NOT NULL,
  `pm_id` int(11) DEFAULT NULL COMMENT '物理机ID外键',
  `os_ver` varchar(50) DEFAULT 'Others' COMMENT '操作系统(Windows/Linux/Others)',
  `purpose` varchar(255) DEFAULT '' COMMENT '用途说明',
  `comment` varchar(255) DEFAULT '' COMMENT '备注',
  PRIMARY KEY (`ip`),
  CONSTRAINT `fk_ip_extend_pm` FOREIGN KEY (`pm_id`) REFERENCES `physical_machines` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
