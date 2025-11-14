import json
import secrets # ### NUEVO ###
import hashlib
import bcrypt # ### NUEVO ###
import mysql.connector
import base64
import shutil
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file
# Se eliminó 'import random'


def loadDatabaseSettings(pathjs):
# ... (código original) ...
	pathjs = Path(pathjs)
	sjson = False
	if pathjs.exists():
		with pathjs.open() as data:
			sjson = json.load(data)
	return sjson

# ### MODIFICADO ###
def getToken():
	# Genera un token aleatorio seguro de 32 bytes (64 caracteres)
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
			# ### MODIFICADO ###
			# Se usa Bcrypt para hashear la contraseña
			password_bytes = request.json["password"].encode('utf-8')
			salt = bcrypt.gensalt()
			hashed_password = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
			
			# (Nota: Esto SIGUE siendo vulnerable a SQLi, se corrige en A03)
			cursor.execute(f'insert into Usuario values(null,"{request.json["uname"]}","{request.json["email"]}", "{hashed_password}")');
			R = cursor.lastrowid
			db.commit()
		db.close()
	except Exception as e:
		print(e) 
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
			# ### MODIFICADO ###
			# 1. Obtener el id y el hash guardado
			# (Nota: Esto SIGUE siendo vulnerable a SQLi, se corrige en A03)
			cursor.execute(f'Select id, password from Usuario where uname ="{request.json["uname"]}"');
			user_data = cursor.fetchone()

			if not user_data:
				db.close()
				return {"R":-3} # Usuario no existe
			
			user_id, stored_hash = user_data
			password_bytes = request.json["password"].encode('utf-8')
			stored_hash_bytes = stored_hash.encode('utf-8')

			# 2. Comparar la contraseña con el hash usando Bcrypt
			if not bcrypt.checkpw(password_bytes, stored_hash_bytes):
				db.close()
				return {"R":-3} # Contraseña incorrecta
			
			# Si la contraseña es correcta, preparamos R para la lógica de token
			R = [(user_id,)] 

	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	
	
	if not R:
		db.close()
		return {"R":-3}
	
	T = getToken(); # Usa la nueva función segura
	
	# ... (El resto de la lógica de token sigue igual) ...
	#file_put_contents('/tmp/log','insert into AccesoToken values('.R[0].',"'.T.'",now())');
	with open("/tmp/log","a") as log:
		log.write(f'Delete from AccesoToken where id_Usuario = "{R[0][0]}"\n')
		log.write(f'insert into AccesoToken values({R[0][0]},"{T}",now())\n')
	
	
	try:
		with db.cursor() as cursor:
			# (Nota: Esto SIGUE siendo vulnerable a SQLi, se corrige en A03)
			cursor.execute(f'Delete from AccesoToken where id_Usuario = "{R[0][0]}"');
			cursor.execute(f'insert into AccesoToken values({R[0][0]},"{T}",now())');
			db.commit()
			db.close()
			return {"R":0,"D":T}
	except Exception as e:
		print(e)
		db.close()
		return {"R":-4}

# ... (El código de /Imagen sigue igual) ...
@post('/Imagen')
def Imagen():
# ... (código original) ...
	#Directorio
	tmp = Path('tmp')
	if not tmp.exists():
		tmp.mkdir()
	img = Path('img')
	if not img.exists():
		img.mkdir()
	
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'name' in request.json  and 'data' in request.json and 'ext' in request.json  and 'token' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)

	# Validar si el usuario esta en la base de datos
	TKN = request.json['token'];
	
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute(f'select id_Usuario from AccesoToken where token = "{TKN}"');
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	
	
	id_Usuario = R[0][0];
	with open(f'tmp/{id_Usuario}',"wb") as imagen:
		imagen.write(base64.b64decode(request.json['data'].encode()))
	
	############################
	############################
	# Guardar info del archivo en la base de datos
	try:
		with db.cursor() as cursor:
			cursor.execute(f'insert into Imagen values(null,"{request.json["name"]}","img/",{id_Usuario})');
			cursor.execute('select max(id) as idImagen from Imagen where id_Usuario = '+str(id_Usuario));
			R = cursor.fetchall()
			idImagen = R[0][0];
			cursor.execute('update Imagen set ruta = "img/'+str(idImagen)+'.'+str(request.json['ext'])+'" where id = '+str(idImagen));
			db.commit()
			# Mover archivo a su nueva locacion
			shutil.move('tmp/'+str(id_Usuario),'img/'+str(idImagen)+'.'+str(request.json['ext']))
			return {"R":0,"D":idImagen}
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-3}

# ... (El código de /Descargar (con fix A01) sigue igual) ...
@post('/Descargar')
def Descargar():
# ... (código con fix A01) ...
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
	
	# TODO validar correo en json
	# Comprobar que el usuario sea valido
	TKN = request.json['token'];
	idImagen = request.json['id'];
	
	R = False
	id_Usuario = None # ### NUEVO ###
	try:
		with db.cursor() as cursor:
			cursor.execute('select id_Usuario from AccesoToken where token = "'+TKN+'"');
			R = cursor.fetchall()
			if not R: # ### NUEVO ### (Validar si el token existe)
				db.close()
				return {"R":-5, "M": "Token Invalido"}
			id_Usuario = R[0][0] # ### NUEVO ### (Guardamos el id del usuario)
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
		
	
	
	# Buscar imagen y enviarla
	
	try:
		with db.cursor() as cursor:
			# ### MODIFICADO ###
			# Se añade "AND id_Usuario = " para verificar la propiedad.
			# (Nota: Esto SIGUE siendo vulnerable a SQLi, que se corrige en A03)
			query = 'Select name,ruta from  Imagen where id = '+str(idImagen)+' AND id_Usuario = '+str(id_Usuario)
			cursor.execute(query);
			R = cursor.fetchall()
			
			if not R: # ### NUEVO ###
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