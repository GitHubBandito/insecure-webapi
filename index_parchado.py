import json
import secrets 
# import hashlib (Ya no es necesario)
import bcrypt 
import mysql.connector
import base64
import shutil
import magic 
import logging # ### NUEVO (A09) ###
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file

# ### NUEVO (A09): Configuración de Logging ###
# Reemplaza los 'print(e)' y logs inseguros
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s:%(message)s')
# -----------------------------------------

# (A08) Lista blanca
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def loadDatabaseSettings(pathjs):
# ... (código original) ...
	pathjs = Path(pathjs)
	sjson = False
	if pathjs.exists():
		with pathjs.open() as data:
			sjson = json.load(data)
	return sjson

def getToken():
# ... (Corregido A02) ...
	return secrets.token_hex(32)

@post('/Registro')
def Registro():
# ... (conexión DB) ...
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	####/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	R = False
	try:
		with db.cursor() as cursor:
			# (Corregido A02)
			password_bytes = request.json["password"].encode('utf-8')
			salt = bcrypt.gensalt()
			hashed_password = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
			
			# (Corregido A03)
			query = "INSERT INTO Usuario (uname, email, password) VALUES (%s, %s, %s)"
			data = (request.json["uname"], request.json["email"], hashed_password)
			cursor.execute(query, data);
			
			R = cursor.lastrowid
			db.commit()
		db.close()
	except Exception as e:
		# ### MODIFICADO (A09) ###
		logging.error(f"Error en /Registro: {e}") 
		return {"R":-2}
	return {"R":0,"D":R}


@post('/Login')
def Login():
# ... (conexión DB) ...
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'uname' in request.json  and 'password' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	user_id = None
	try:
		with db.cursor() as cursor:
			# (Corregido A03)
			query = "SELECT id, password FROM Usuario WHERE uname = %s"
			cursor.execute(query, (request.json["uname"],));
			user_data = cursor.fetchone()

			if not user_data:
				db.close()
				# ### NUEVO (A09) ###
				logging.warning(f"Intento de login fallido (usuario no existe): {request.json['uname']}")
				return {"R":-3}
			
			user_id, stored_hash = user_data
			password_bytes = request.json["password"].encode('utf-8')
			stored_hash_bytes = stored_hash.encode('utf-8')

			# (Corregido A02)
			if not bcrypt.checkpw(password_bytes, stored_hash_bytes):
				db.close()
				# ### NUEVO (A09) ###
				logging.warning(f"Intento de login fallido (pass incorrecta): {request.json['uname']}")
				return {"R":-3}
			
			R = [(user_id,)] 

	except Exception as e: 
		# ### MODIFICADO (A09) ###
		logging.error(f"Error en /Login (autenticando): {e}")
		db.close()
		return {"R":-2}
	
	
	if not R:
		db.close()
		return {"R":-3}
	
	T = getToken(); # (Corregido A02)
	
	# (El log inseguro de /tmp se eliminó en el paso A03)
	
	try:
		with db.cursor() as cursor:
			user_id = R[0][0]
			
			# (Corregido A03)
			query_del = "DELETE FROM AccesoToken WHERE id_Usuario = %s"
			cursor.execute(query_del, (user_id,));
			
			query_ins = "INSERT INTO AccesoToken VALUES (%s, %s, now())"
			cursor.execute(query_ins, (user_id, T));
			
			db.commit()
			db.close()
			return {"R":0,"D":T}
	except Exception as e:
		# ### MODIFICADO (A09) ###
		logging.error(f"Error en /Login (creando token): {e}")
		db.close()
		return {"R":-4}

@post('/Imagen')
def Imagen():
# ... (crear directorios) ...
	#Directorio
	tmp = Path('tmp')
	if not tmp.exists():
		tmp.mkdir()
	img = Path('img')
	if not img.exists():
		img.mkdir()
	
	if not request.json:
		return {"R":-1}
	R = 'name' in request.json  and 'data' in request.json and 'ext' in request.json  and 'token' in request.json
	if not R:
		return {"R":-1}
	
	# (Corregido A08)
	user_ext = request.json['ext'].lower()
	if user_ext not in ALLOWED_EXTENSIONS:
		return {"R": -5, "M": "Extensión de archivo no permitida"}

	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)

	TKN = request.json['token'];
	
	id_Usuario = None
	try:
		with db.cursor() as cursor:
			# (Corregido A03)
			query = "SELECT id_Usuario FROM AccesoToken WHERE token = %s"
			cursor.execute(query, (TKN,));
			R = cursor.fetchall()
			if not R:
				db.close()
				return {"R":-5, "M":"Token inválido"}
			id_Usuario = R[0][0]
	except Exception as e: 
		# ### MODIFICADO (A09) ###
		logging.error(f"Error en /Imagen (validando token): {e}")
		db.close()
		return {"R":-2}
	
	
	# (Corregido A08)
	try:
		file_data = base64.b64decode(request.json['data'].encode())
	except Exception:
		db.close()
		return {"R": -6, "M": "Base64 inválido"}

	mime_type = magic.from_buffer(file_data, mime=True)
	if not mime_type.startswith('image/'):
		db.close()
		return {"R": -7, "M": "El contenido no es una imagen válida"}
	# ------------------------------------

	with open(f'tmp/{id_Usuario}',"wb") as imagen:
		imagen.write(file_data)
	
	try:
		with db.cursor() as cursor:
			# (Corregido A03)
			query_ins = "INSERT INTO Imagen (name, ruta, id_Usuario) VALUES (%s, %s, %s)"
			cursor.execute(query_ins, (request.json["name"], "img/", id_Usuario));
			
			idImagen = cursor.lastrowid
			
			# (Corregido A08)
			ruta_final = f"img/{idImagen}.{user_ext}"
			
			# (Corregido A03)
			query_upd = "UPDATE Imagen SET ruta = %s WHERE id = %s"
			cursor.execute(query_upd, (ruta_final, idImagen));
			
			db.commit()
			
			shutil.move(f'tmp/{id_Usuario}', ruta_final)
			return {"R":0,"D":idImagen}
	except Exception as e: 
		# ### MODIFICADO (A09) ###
		logging.error(f"Error en /Imagen (guardando archivo/db): {e}")
		db.close()
		return {"R":-3}
	

@post('/Descargar')
def Descargar():
# ... (conexión DB) ...
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	
	
	if not request.json:
		return {"R":-1}
	R = 'token' in request.json and 'id' in request.json  
	if not R:
		return {"R":-1}
	
	TKN = request.json['token'];
	idImagen = request.json['id'];
	
	id_Usuario = None
	try:
		with db.cursor() as cursor:
			# (Corregido A03)
			query = "SELECT id_Usuario FROM AccesoToken WHERE token = %s"
			cursor.execute(query, (TKN,));
			R = cursor.fetchall()
			if not R:
				db.close()
				return {"R":-5, "M": "Token Invalido"}
			id_Usuario = R[0][0]
	except Exception as e: 
		# ### MODIFICADO (A09) ###
		logging.error(f"Error en /Descargar (validando token): {e}")
		db.close()
		return {"R":-2}
		
	
	# Buscar imagen y enviarla
	try:
		with db.cursor() as cursor:
			# (Corregido A01 y A03)
			query = "SELECT name, ruta FROM Imagen WHERE id = %s AND id_Usuario = %s"
			data = (idImagen, id_Usuario)
			cursor.execute(query, data);
			R = cursor.fetchall()
			
			if not R:
				db.close()
				return {"R":-4, "M": "Imagen no encontrada o acceso denegado"}
				
	except Exception as e: 
		# ### MODIFICADO (A09) ###
		logging.error(f"Error en /Descargar (buscando imagen): {e}")
		db.close()
		return {"R":-3}
	
	# print(Path("img").resolve(),R[0][1]) # Eliminamos el print de debug
	return static_file(R[0][1],Path(".").resolve())

if __name__ == '__main__':
	# ### MODIFICADO (A05) ###
    run(host='localhost', port=8080, debug=False)