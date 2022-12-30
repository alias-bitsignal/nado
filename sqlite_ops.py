import sqlite3


class DbHandler:
    def __init__(self, db_file):
        self.con = sqlite3.connect(db_file)
        self.cur = self.con.cursor()

    def db_execute(self, query, *args):
        try:
            with self.con:
                self.cur.execute(query, *args)
                self.con.commit()
            return True
        except Exception as e:
            return False

    def db_fetch(self, query, *args):
        try:
            with self.con:
                self.cur.execute(query, *args)
                result = self.cur.fetchall()
            return result
        except Exception as e:
            return False

    def close(self):
        self.con.close()


if __name__ == "__main__":
    dbhandler = DbHandler(db_file="test.db")
    dbhandler.db_execute("CREATE TABLE IF NOT EXISTS tx_index(txid UNIQUE, block_number INTEGER)")
    dbhandler.db_execute("INSERT INTO tx_index VALUES (?, ?)", ('a', '1'))
    dbhandler.db_execute("INSERT INTO tx_index VALUES (?, ?)", ('b', '2'))
    dbhandler.db_execute("DELETE FROM tx_index WHERE block_number = ?", '1')

    print(dbhandler.db_fetch("SELECT * FROM tx_index WHERE block_number = ?", '2'))
    dbhandler.close()