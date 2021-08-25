import sqlite3 as sq

con = sq.connect('tuff.db')
cur = con.cursor()

cur.execute('''CREATE TABLE maintable
			   (id integer NOT NULL primary key AUTOINCREMENT,
			   Date date,
			   Time time,
			   MACsource text,
			   MACdest text,
			   IPsource text,
			   IPdest text,
			   Protocol text,
               len int,
			   info text,
			   binary blob,
			   hexdump text)''')

con.commit()
con.close()