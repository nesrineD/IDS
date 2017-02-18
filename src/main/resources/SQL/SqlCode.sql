Drop database ids;
create database ids;
Use ids;

CREATE TABLE Train (
  id varchar(20) DEFAULT NULL,
  SrcIp varchar(50) DEFAULT NULL,
  DestIp varchar(50) DEFAULT NULL,
  Protocol varchar(10) DEFAULT NULL,
  PacketLength varchar(50) DEFAULT NULL,
  DF_flag varchar(50) DEFAULT NULL,
  MF_flag varchar(50) DEFAULT NULL,
  Resv_flag varchar(50) DEFAULT NULL,
  TTL varchar(50) DEFAULT NULL,
  TOS varchar(50) DEFAULT NULL,
  CheckSum varchar(50) DEFAULT NULL,
  PayloadLength varchar(50) DEFAULT NULL,
  timestamp_ varchar(50) DEFAULT NULL,
  srcPort varchar(50) DEFAULT NULL,
  dstPort varchar(50) DEFAULT NULL,
  Psh varchar(50) DEFAULT NULL,
  Urg varchar(50) DEFAULT NULL,
  ACK varchar(50) DEFAULT NULL,
  RST varchar(50) DEFAULT NULL,
  SYN varchar(50) DEFAULT NULL,
  FIN varchar(50) DEFAULT NULL,
  reserved varchar(50) DEFAULT NULL,
  window varchar(50) DEFAULT NULL,
  ack_num varchar(50) DEFAULT NULL,
  seq_num varchar(50) DEFAULT NULL,
  category varchar(50) DEFAULT NULL
);