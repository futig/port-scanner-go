package domain

var StandartPorts = map[int]string{
	80:   "HTTP",
	443:  "HTTPS",
	20:   "FTP",
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	69:   "TFTP",
	110:  "POP3",
	143:  "IMAP",
	161:  "SNMP",
	179:  "BGP",
	389:  "LDAP",
	636:  "LDAPS",
	3389: "RDP",
	3306: "MySQL",
	5432: "PostgreSQL",
	123:  "NTP",
	88:   "Kerberos",
	445:  "SMB",
}
