from flask import Flask
from flask import jsonify
from flask import request
#Cors para hacer comunicacion cruzada entre diferentes herramientas 
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re

from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


app = Flask(__name__)
cors = CORS(app)

app.config["JWT_SECRET_KEY"]="super-secret" #Cambiar por el que sea conveniente
jwt = JWTManager(app)


@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-security"]+'/usuarios/validate'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60*24)
        access_token = create_access_token(identity=user,expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Bad username or password"}), 401

#####################################creacion de los Middleware##########################
@app.before_request
def before_request_callback():
    endPoint=limpiarURL(request.path)
    excludedRoutes=["/login"]
    if excludedRoutes.__contains__(request.path):
        #print("ruta excluida ",request.path)
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["role"]is not None:
            tienePersmiso=validarPermiso(endPoint,request.method,usuario["role"]["_id"])
            #print(f'El estado del permiso del usuario es: {tienePersmiso}')
            if not tienePersmiso:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401
def limpiarURL(url):
    partes = request.path.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url

def validarPermiso(endPoint,metodo,idRol):
    url=dataConfig["url-backend-security"]+"/permisos-roles/validar-permiso/rol/"+str(idRol) 
    #print(idRol)
    tienePermiso=False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body={
        "url":endPoint,
        "method":metodo
    }
    response = requests.get(url,json=body, headers=headers)
    try:
        data=response.json()
        if("_id" in data):
            tienePermiso=True
    except:
        pass
    #print(tienePermiso)
    return tienePermiso
    
############################################################################################

##########################Implementacion redireccionamiento Backend-Academico##############
#####################################Estudiante#################################
@app.route("/estudiantes",methods=['GET'])
def getStudents():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/students'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/estudiantes",methods=['POST'])
def createStudent():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/students'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/estudiantes/<string:id>",methods=['GET'])
def getStudent(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/students/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/estudiantes/<string:id>",methods=['PUT'])
def updateStudent(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/students/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/estudiantes/<string:id>",methods=['DELETE'])
def deleteStudent(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/students/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
#######################################Materias#################################
@app.route("/materias",methods=['GET'])
def getCourses():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/course'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/materias",methods=['POST'])
def createCourse():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/course'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/materias/<string:id>",methods=['GET'])
def getCourse(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/course/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/materias/<string:id>",methods=['PUT'])
def updateCourse(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/course/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/materias/<string:id>",methods=['DELETE'])
def deleteCourse(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/course/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
###########################Relacion [1:n} Materia-departamento########################
@app.route("/materias/<string:id>/departamento/<string:idDepartment>",methods=['PUT'])
def assignDepartmentToCourse(id,idDepartment):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/course/' + id + '/departamento/' + idDepartment
    response = requests.put(url, headers=headers)
    json = response.json()
    return jsonify(json)
####################################departamento########################
@app.route("/departamentos",methods=['GET'])
def getDepartments():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/department'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/departamentos",methods=['POST'])
def createDepartment():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/department'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/departamentos/<string:id>",methods=['GET'])
def getDepartment(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/department/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/departamentos/<string:id>",methods=['PUT'])
def updateDepartment(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/department/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/departamentos/<string:id>",methods=['DELETE'])
def deleteDepartment(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/department/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

#####################Relacion [n:n] inscripcion: estudiante-materia###################
@app.route("/inscripcion",methods=['GET'])
def getInscriptions():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] +'/inscripciones'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/inscripcion/estudiante/<string:idStudent>/materia/<string:idCourse>",methods=['POST'])
def createInscription(idStudent,idCourse):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inscripcion/estudiante/'+idStudent+'/materia/'+idCourse
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/inscripcion/<string:id>",methods=['GET'])
def getInscription(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inscripcion/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/inscripcion/<string:id>/estudiante/<string:idStudent>/materia/<string:idCourse>",methods=['PUT'])
def updateInscription(id,idStudent,idCourse):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inscripciones/'+ id + '/estudiante/' + idStudent + '/materia/' + idCourse
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/inscripcion/<string:id>",methods=['DELETE'])
def deleteInscription(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inscripcion/' + id 
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


###################################Querys de inscripcion#############################################

@app.route("/inscripcion/materias/<string:idMaterias>",methods=['GET'])
def getListInscribedInCourse(idMaterias):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inscripcion/materias/'+idMaterias
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/inscripcion/nota_mayor_por_curso",methods=['GET'])
def getGreaterValue():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inscripcion/nota_mayor_por_curso' 
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/inscripcion/promedio_por_materia/<string:idMaterias>",methods=['GET'])
def getAVGCourse(idMaterias):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inscripcion/promedio_por_materia/'+idMaterias
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
############################################################################################

##############Implementacion redireccionamiento Backend-Seguridad###########################
###########################Permisos#########################################################
@app.route("/permisos",methods=['GET'])
def getPermissions():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permisos",methods=['POST'])
def createPermission():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/permisos/<string:id>",methods=['GET'])
def getPermission(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permisos/<string:id>",methods=['PUT'])
def updatePermission(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos/'+id
    response = requests.put(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/permisos/<string:id>",methods=['DELETE'])
def deletePermission(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos/'+id
    response = requests.delete(url, headers=headers)
    return jsonify({"deleted": "permiso"})
########################### Usuarios ########################################################
@app.route("/usuarios",methods=['GET'])
def getUsers():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios",methods=['POST'])
def createUser():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['GET'])
def getUser(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['PUT'])
def updateUser(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/'+id
    response = requests.put(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['DELETE'])
def deleteUser(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/'+id
    response = requests.delete(url, headers=headers)
    return jsonify({"deleted": "usuarios"})

########################### Usuarios-roles: relacion [1:n] ###############################
@app.route("/usuarios/<string:idUser>/rol/<string:idRole>",methods=['PUT'])
def updateUserWithRole(idUser,idRole):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/'+idUser+'/rol/'+idRole
    response = requests.put(url, headers=headers)
    json = response.json()
    return jsonify(json)

######################################### Validar Usuarios ###############################
@app.route("/usuarios/validar",methods=['POST'])
def ValidateUser():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/validate'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
########################### Roles ########################################################
@app.route("/roles",methods=['GET'])
def getRoles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/roles",methods=['POST'])
def createRole():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/roles/<string:id>",methods=['GET'])
def getRole(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/roles/<string:id>",methods=['PUT'])
def updateRole(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles/'+id
    response = requests.put(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/roles/<string:id>",methods=['DELETE'])
def deleteRole(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles/'+id
    response = requests.delete(url, headers=headers)
    return jsonify({"deleted": "roles"})
################################# Permisos roles: Relacion [n:n] ##########################
@app.route("/permisos-roles",methods=['GET'])
def getPermissionsRoles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permisos-roles/rol/<string:idRole>/permiso/<string:idPermission>",methods=['POST'])
def createPermissionRole(idRole,idPermission):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/rol/'+idRole+'/permiso/'+idPermission
    response = requests.post(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permisos-roles/<string:id>",methods=['GET'])
def getPermissionRole(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permisos-roles/<string:id>/rol/<string:idRole>/permiso/<string:idPermission>",methods=['PUT'])
def updatePermissionRole(id,idRole,idPermission):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"]+'/permisos-roles/'+id+'/rol/'+idRole+'/permiso/'+idPermission
    response = requests.put(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permisos-roles/<string:id>",methods=['DELETE'])
def deletePermissionRole(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/'+id
    response = requests.delete(url, headers=headers)
    return jsonify({"deleted": "permisos-roles"})

######################################### Validar permisos roles ##########################
@app.route("/permisos-roles/validar-permiso/rol/<string:idRole>",methods=['GET'])
def ValidatePermissionRole(idRole):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/validar-permiso/rol/'+idRole
    response = requests.get(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
###########################################################################################
@app.route("/",methods=['GET'])
def test():
    json = {}
    json["message"]="Server running ..."
    return jsonify(json)

def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data 

if __name__=='__main__':
    dataConfig = loadFileConfig()
    print("Server running : "+"http://"+dataConfig["url-backend"]+":" + str(dataConfig["port"]))
    serve(app,host=dataConfig["url-backend"],port=dataConfig["port"])
