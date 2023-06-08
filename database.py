#引入pymysql模块
import pymysql

class DoMysql:
    #初始化
    def __init__(self):
        #创建连接
        self.conn = pymysql.Connect(
          host = 'localhost',
          port = 3306,
          user = 'root',
          password = 'root',
          db = 'test',
          charset = 'utf8',
          cursorclass = pymysql.cursors.DictCursor  #以字典的形式返回数据
        )
        #获取游标
        self.cursor = self.conn.cursor()

    #返回多条数据
    def fetchAll(self, sql, params):
        self.cursor.execute(sql, params)
        return self.cursor.fetchall()

    #插入一条数据
    def insert_one(self, sql, params):
        result = self.cursor.execute(sql, params)
        self.conn.commit()
        return result

    #更新数据
    def update(self, sql, params):
        result = self.cursor.execute(sql, params)
        self.conn.commit()
        return result

    def select(self, sql, params):
        result = self.cursor.execute(sql, params)
        self.conn.commit()
        return result

    #关闭连接
    def close(self):
        self.cursor.close()
        self.conn.close()

if __name__ == '__main__':
    mysql  = DoMysql()
    params = ("123r1hjv", 4123)
    #插入一条数据
    #sql = 'insert into `file`(`hash`,`v`) values(%s,%s)'
    #result = mysql.insert_one(sql, params)
    #print(result) #返回插入数据的条数(1)

    #更新数据
    sql = 'update file set h = %s, r = %s, S = %s where hash = %s'
    params = (1,2,3,"123r1hjv")
    mysql.update(sql, params)

    #关闭连接
    mysql.close()