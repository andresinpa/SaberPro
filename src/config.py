from psycopg2 import connect

#HOST = 'localhost' 
#PORT = 5432
#BD = 'bd_personas'
#USUARIO = 'postgres'
#PASSWORD = 'thor'

HOST = 'localhost'
PORT = 5432
BD = 'bd_udecsoft'
USUARIO = 'postgres'
PASSWORD = 'root'

def EstablecerConexion():
    try:
        conexion =connect(host=HOST,port=PORT,database=BD, user=USUARIO, password=PASSWORD)
    except ConnectionError:
       print("Error de Conexión")
       
    return conexion 