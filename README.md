# SystemLoginFlask
*Sistema de login feito com flask, utilizando senhas encriptografadas e tokens*
### Partes
1. endpoints
2. 

## Endpoints
```
from resources.UsuarioResource import UsuarioResource
from resources.AuthResource import AuthResource

api.add_resource(UsuarioResource, "/usuario")
api.add_resource(AuthResource, "/login")
```
UsuarioResource
```
from flask_restful import Resource, marshal_with
from flask import request
from models.TB_Usuario import TB_Usuario, TB_UsuarioSchema, tb_usuario_fields
from helpers.database import db

schema = TB_UsuarioSchema()

class UsuarioResource(Resource):

    @marshal_with(tb_usuario_fields)
    def post(self):

        data = schema.load(request.json)

        usuario = TB_Usuario(
            usuario_nome=data["usuario_nome"],
            email=data["email"],
            funcao=data["funcao"]
        )

        usuario.set_senha(data["senha"])

        db.session.add(usuario)
        db.session.commit()

        return usuario, 201
```
AuthResource
```
from flask_restful import Resource
from flask import request
from models.TB_Usuario import TB_Usuario

from flask_jwt_extended import create_access_token

class AuthResource(Resource):

    def post(self):

        email = request.json.get("email")
        senha = request.json.get("senha")

        usuario = TB_Usuario.query.filter_by(email=email).first()

        if not usuario:
            return {"message": "Usuário não encontrado"}, 404

        if not usuario.check_senha(senha):
            return {"message": "Senha incorreta"}, 401
        
        access_token = create_access_token(
            identity=usuario.usuario_id,
            additional_claims={
                "funcao": usuario.funcao
            }
        )

        return {
            "message": "Login realizado com sucesso",
            "access_token": access_token,
            "usuario": usuario.usuario_nome,
            "funcao": usuario.funcao
        }, 200
```
TB_Usuario
```
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, Integer
from helpers.database import db
from marshmallow import Schema, fields, validate, ValidationError, validates
from flask_restful import fields as flaskFields

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

tb_usuario_fields = {
    'usuario_id': flaskFields.Integer,
    'usuario_nome': flaskFields.String,
    'email': flaskFields.String,
    'funcao': flaskFields.String
}

class TB_Usuario(db.Model):
    __tablename__ = "tb_usuario"

    usuario_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    usuario_nome: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    senha: Mapped[str] = mapped_column(String(255), nullable=False)
    funcao: Mapped[str] = mapped_column(String(255), nullable=False)
    
    def set_senha(self, senha_plain: str):
        self.senha = ph.hash(senha_plain)

    def check_senha(self, senha_plain: str):
        try:
            return ph.verify(self.senha, senha_plain)
        except VerifyMismatchError:
            return False

class TB_UsuarioSchema(Schema):
    usuario_id = fields.Int(dump_only=True)
    usuario_nome = fields.Str(
        required=True,
        validate=validate.Length(min=3, max=255),
        error_messages={
            "required": "O campo usuario_nome é obrigatório",
            "null": "O campo usuario_nome não pode ser nulo.",
            "validator_failed": "O campo usuario_nome deve ter entre 2 a 255 caracteres."
        }
    )
    email = fields.Email(
        required=True,
        error_messages={
            "required": "O campo email é obrigatório",
            "invalid": "Email inválido"
        }
    )
    senha = fields.Str(
        required=True,
        validate=validate.Length(min=8, max=255),
        error_messages={
            "required": "O campo senha é obrigatório",
            "null": "O campo senha não pode ser nulo.",
            "validator_failed": "O campo senha deve ter no mínimo 8 dígitos."
        }
    )
    funcao = fields.Str(
        required=True,
        validate=validate.Length(min=3, max=255),
        error_messages={
            "required": "O campo funcao é obrigatório",
            "null": "O campo funcao não pode ser nulo.",
            "validator_failed": "O campo funcao deve ter entre 2 a 255 caracteres."
        }
    )


```
##
