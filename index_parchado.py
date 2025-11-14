import json
import secrets 
import hashlib
import bcrypt 
import mysql.connector
import base64
import shutil
import magic # ### NUEVO (A08) ###
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file

# ### NUEVO (A08) ###
# Lista blanca de extensiones permitidas
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def loadDatabaseSettings(pathjs):
# ... (código anterior) ...
	pathjs = Path(pathjs)
	sjson = False
	if pathjs.exists():
		with pathjs.open() as data:
			sjson = json.load(data)
	return sjson

def getToken():
# ... (código anterior) ...
	return secrets.token_hex(32)

@post('/Registro')
def Registro():
# ... (código corregido A02, A03) ...
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
			password_bytes = request.json["password"].encode('utf-8')
			salt = bcrypt.gensalt()
			hashed_password = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
			
			# ### MODIFICADO (A03) ###
			# Se usan consultas parametrizadas
			query = "INSERT INTO Usuario (uname, email, password) VALUES (%s, %s, %s)"
			data = (request.json["uname"], request.json["email"], hashed_password)
			cursor.execute(query, data);
			
			R = cursor.lastrowid
			db.commit()
		db.close()
	except Exception as e:
		print(e) 
		return {"R":-2}
	return {"R":0,"D":R}

@post('/Login')
def Login():
# ... (código corregido A02, A03) ...
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
			# ### MODIFICADO (A03) ###
			# 1. Obtener hash (Consulta parametrizada)
			query = "SELECT id, password FROM Usuario WHERE uname = %s"
			cursor.execute(query, (request.json["uname"],));
			user_data = cursor.fetchone()

			if not user_data:
				db.close()
				return {"R":-3}
			
			user_id, stored_hash = user_data
			password_bytes = request.json["password"].encode('utf-8')
			stored_hash_bytes = stored_hash.encode('utf-8')

			if not bcrypt.checkpw(password_bytes, stored_hash_bytes):
				db.close()
				return {"R":-3}
			
			R = [(user_id,)] 

	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	
	
	if not R:
		db.close()
		return {"R":-3}
	
	T = getToken();
	
	# ### MODIFICADO (A03) ###
	# Se elimina el log inseguro de /tmp (Parte de A05/A09, pero lo quitamos
	# al reescribir esta sección)
	
	try:
		with db.cursor() as cursor:
			user_id = R[0][0] # Obtenemos el id de forma limpia
			
			# ### MODIFICADO (A03) ###
			# Consultas parametrizadas para gestionar tokens
			query_del = "DELETE FROM AccesoToken WHERE id_Usuario = %s"
			cursor.execute(query_del, (user_id,));
			
			query_ins = "INSERT INTO AccesoToken VALUES (%s, %s, now())"
			cursor.execute(query_ins, (user_id, T));
			
			db.commit()
			db.close()
			return {"R":0,"D":T}
	except Exception as e:
		print(e)
		db.close()
		return {"R":-4}


@post('/Imagen')
def Imagen():
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
	
	# ### NUEVO (A08): Validar extensión ---
	user_ext = request.json['ext'].lower()
	if user_ext not in ALLOWED_EXTENSIONS:
		return {"R": -5, "M": "Extensión de archivo no permitida"}
	# ------------------------------------

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
		print(e)
		db.close()
		return {"R":-2}
	
	
	# ### NUEVO (A08): Validar contenido ---
	try:
		file_data = base64.b64decode(request.json['data'].encode())
	except Exception:
		db.close()
		return {"R": -6, "M": "Base64 inválido"}

	# Validar el tipo de archivo real (MIME type)
	mime_type = magic.from_buffer(file_data, mime=True)
	if not mime_type.startswith('image/'):
		db.close()
		return {"R": -7, "M": "El contenido no es una imagen válida"}
	# ------------------------------------

	# Escribir el archivo validado
	with open(f'tmp/{id_Usuario}',"wb") as imagen:
		imagen.write(file_data) # Escribimos los datos ya decodificados
	
	try:
		with db.cursor() as cursor:
			# (Corregido A03)
			query_ins = "INSERT INTO Imagen (name, ruta, id_Usuario) VALUES (%s, %s, %s)"
			cursor.execute(query_ins, (request.json["name"], "img/", id_Usuario));
			
			idImagen = cursor.lastrowid
			
			# ### MODIFICADO (A08) ###
			# Usamos la 'user_ext' validada, no la del JSON
			ruta_final = f"img/{idImagen}.{user_ext}"
			
			# (Corregido A03)
			query_upd = "UPDATE Imagen SET ruta = %s WHERE id = %s"
			cursor.execute(query_upd, (ruta_final, idImagen));
			
			db.commit()
			
			# ### MODIFICADO (A08) ###
			# Mover el archivo usando la ruta final segura
			shutil.move(f'tmp/{id_Usuario}', ruta_final)
			return {"R":0,"D":idImagen}
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-3}
	
@post('/Descargar')
def Descargar():
# ... (código corregido A01, A03) ...
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
	R = 'token' in request.json and 'id' in request.json  
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	TKN = request.json['token'];
	idImagen = request.json['id'];
	
	R = False
	id_Usuario = None
	try:
		with db.cursor() as cursor:
			# ### MODIFICADO (A03) ###
			query = "SELECT id_Usuario FROM AccesoToken WHERE token = %s"
			cursor.execute(query, (TKN,));
			R = cursor.fetchall()
			if not R:
				db.close()
				return {"R":-5, "M": "Token Invalido"}
			id_Usuario = R[0][0]
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
		
	
	# Buscar imagen y enviarla
	try:
		with db.cursor() as cursor:
			# ### MODIFICADO (A03) ###
			# Esta consulta ahora corrige A03 (SQLi) y ya tenía la
			# corrección de A01 (Access Control)
			query = "SELECT name, ruta FROM Imagen WHERE id = %s AND id_Usuario = %s"
			data = (idImagen, id_Usuario)
			cursor.execute(query, data);
			R = cursor.fetchall()
			
			if not R:
				db.close()
				return {"R":-4, "M": "Imagen no encontrada o acceso denegado"}
				
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-3}
	print(Path("img").resolve(),R[0][1])
	return static_file(R[0][1],Path(".").resolve())

if __name__ == '__main__':
    run(host='localhost', port=8080, debug=True)