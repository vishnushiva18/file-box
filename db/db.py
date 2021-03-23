import mysql.connector
from mysql.connector import Error
import json

def select(connectionId, query):
    json_data=[]
    
    json_result = {"status" : True, "data" : []}
    connection = False
    
    try:
        connection = mysql.connector.connect(host=connectionId['host'],
                                    database=connectionId['database'],
                                    user=connectionId['user'],
                                    password=connectionId['password'])
        
        if connection.is_connected():
            cursor = connection.cursor()
            cursor.execute(query)
            row_headers=[x[0] for x in cursor.description]
            record = cursor.fetchall()
            for result in record:
                    json_data.append(dict(zip(row_headers,result)))
            
            json_result['data']=json_data

    except Error as e:
        json_result = {"status" : False, "status_message" : e, "data" : []}
        return json_result
    finally:
        if connection:
            if connection.is_connected():
                cursor.close()
                connection.close()

    return json_result

def execute(connectionId, query):
    json_data=[]
    
    json_result = {"status" : True, "data" : []}

    try: 
        connection = mysql.connector.connect(host=connectionId['host'],
                                    database=connectionId['database'],
                                    user=connectionId['user'],
                                    password=connectionId['password'])
                                    
        if connection.is_connected():
            cursor = connection.cursor()
            cursor.execute(query)
        
            rowid=0
            if cursor.lastrowid:
                rowid=cursor.lastrowid
                
            connection.commit()
            json_result['data']={'rowid' : rowid}
    except Error as e:
        json_result = {"status" : False, "status_message" : e, "data" : []}
    finally:
        if connection:
            if connection.is_connected():
                cursor.close()
                connection.close()

    return json_result