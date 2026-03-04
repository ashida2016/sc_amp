ALTER TABLE ip_extend 
ADD COLUMN device_type varchar(50) DEFAULT 'Any' COMMENT '设备分类',
ADD COLUMN hostname varchar(255) DEFAULT 'TBD/待定' COMMENT '主机名',
ADD COLUMN status varchar(50) DEFAULT 'Reserved' COMMENT '状态',
ADD COLUMN updated_time timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '最后更新日期';
