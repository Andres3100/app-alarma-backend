from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta, timezone
from typing import Optional
import firebase_admin
from firebase_admin import credentials, messaging
import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
import jwt

# ──────────────────────────────────────────
# CONFIGURACIÓN
# ──────────────────────────────────────────

app = FastAPI(title="App Alarma API - Multi-Barrio")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

JWT_SECRET = os.environ.get("JWT_SECRET", "cambia-esto-en-produccion-por-algo-largo-y-seguro")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 365 * 5  # 5 años

# ──────────────────────────────────────────
# FIREBASE
# ──────────────────────────────────────────

google_credentials = os.environ.get("GOOGLE_CREDENTIALS")
if google_credentials:
    cred_dict = json.loads(google_credentials)
    cred = credentials.Certificate(cred_dict)
else:
    cred = credentials.Certificate("serviceAccount.json")
firebase_admin.initialize_app(cred)

# ──────────────────────────────────────────
# BASE DE DATOS
# ──────────────────────────────────────────

def get_db():
    DATABASE_URL = os.environ.get("DATABASE_URL")
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Tabla de barrios / proyectos
    cur.execute("""
        CREATE TABLE IF NOT EXISTS barrios (
            id SERIAL PRIMARY KEY,
            nombre VARCHAR(200) NOT NULL,
            direccion VARCHAR(300),
            ciudad VARCHAR(100),
            codigo_unico VARCHAR(20) UNIQUE NOT NULL,
            activo BOOLEAN DEFAULT TRUE,
            creado_en TIMESTAMP DEFAULT NOW()
        )
    """)

    # Agregar columnas nuevas si no existen
    cur.execute("""
        ALTER TABLE barrios 
        ADD COLUMN IF NOT EXISTS telefono_vigilante VARCHAR(20),
        ADD COLUMN IF NOT EXISTS telefono_presidente VARCHAR(20)
    """)

    # Tabla de usuarios (3 roles)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id SERIAL PRIMARY KEY,
            barrio_id INTEGER REFERENCES barrios(id),
            nombre VARCHAR(200) NOT NULL,
            email VARCHAR(200) UNIQUE NOT NULL,
            telefono VARCHAR(20),
            casa VARCHAR(100),
            password_hash TEXT NOT NULL,
            rol VARCHAR(20) NOT NULL CHECK (rol IN ('superadmin', 'admin_barrio', 'vecino')),
            activo BOOLEAN DEFAULT TRUE,
            creado_en TIMESTAMP DEFAULT NOW()
        )
    """)

    # Tabla de alertas (asociadas a un barrio)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alertas (
            id SERIAL PRIMARY KEY,
            barrio_id INTEGER REFERENCES barrios(id) NOT NULL,
            usuario_id INTEGER REFERENCES usuarios(id),
            casa VARCHAR(200),
            vecino VARCHAR(200),
            tipo VARCHAR(50),
            descripcion TEXT,
            hora VARCHAR(20),
            activa BOOLEAN DEFAULT TRUE,
            creado_en TIMESTAMP DEFAULT NOW()
        )
    """)

    # Tabla de tokens (FCM + refresh tokens)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            id SERIAL PRIMARY KEY,
            usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
            barrio_id INTEGER REFERENCES barrios(id),
            tipo VARCHAR(20) NOT NULL CHECK (tipo IN ('fcm', 'refresh')),
            token TEXT NOT NULL,
            expira_en TIMESTAMP,
            creado_en TIMESTAMP DEFAULT NOW()
        )
    """)

# Tabla de códigos de activación de barrios
    cur.execute("""
        CREATE TABLE IF NOT EXISTS codigos_activacion (
            id SERIAL PRIMARY KEY,
            codigo VARCHAR(50) UNIQUE NOT NULL,
            creado_por INTEGER REFERENCES usuarios(id),
            usado BOOLEAN DEFAULT FALSE,
            usado_en TIMESTAMP,
            barrio_id INTEGER REFERENCES barrios(id),
            notas TEXT,
            creado_en TIMESTAMP DEFAULT NOW()
        )
    """)
    # Crear superadmin por defecto si no existe
    cur.execute("SELECT id FROM usuarios WHERE rol = 'superadmin' LIMIT 1")
    if not cur.fetchone():
        password_hash = bcrypt.hashpw(
            os.environ.get("SUPERADMIN_PASSWORD", "superadmin123").encode(),
            bcrypt.gensalt()
        ).decode()
        cur.execute("""
            INSERT INTO usuarios (nombre, email, password_hash, rol)
            VALUES ('Super Administrador', %s, %s, 'superadmin')
        """, (
            os.environ.get("SUPERADMIN_EMAIL", "admin@appalarma.com"),
            password_hash
        ))

    conn.commit()
    cur.close()
    conn.close()


init_db()

# ──────────────────────────────────────────
# MODELOS
# ──────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

class CrearBarrioRequest(BaseModel):
    nombre: str
    direccion: Optional[str] = None
    ciudad: Optional[str] = None
    email_admin: str
    nombre_admin: str
    password_admin: str
    telefono_admin: Optional[str] = None

class CrearVecinoRequest(BaseModel):
    nombre: str
    email: str
    password: str
    telefono: Optional[str] = None
    casa: str

class AlertaRequest(BaseModel):
    tipo: str
    descripcion: Optional[str] = None

class TokenFCMRequest(BaseModel):
    token: str

class RevocarSesionRequest(BaseModel):
    usuario_id: int
class CrearCodigoRequest(BaseModel):
    notas: Optional[str] = None


class ActivarBarrioRequest(BaseModel):
    codigo: str
    nombre_barrio: str
    direccion: Optional[str] = None
    ciudad: Optional[str] = None
    nombre_admin: str
    email_admin: EmailStr
    telefono_admin: Optional[str] = None
    password_admin: str
# ──────────────────────────────────────────
# JWT HELPERS
# ──────────────────────────────────────────

def crear_access_token(usuario_id: int, barrio_id: Optional[int], rol: str) -> str:
    expira = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(usuario_id),
        "barrio_id": barrio_id,
        "rol": rol,
        "tipo": "access",
        "exp": expira
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def crear_refresh_token(usuario_id: int, barrio_id: Optional[int], rol: str) -> tuple[str, datetime]:
    expira = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": str(usuario_id),
        "barrio_id": barrio_id,
        "rol": rol,
        "tipo": "refresh",
        "exp": expira
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, expira


def verificar_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


def get_usuario_actual(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    payload = verificar_token(credentials.credentials)
    if payload.get("tipo") != "access":
        raise HTTPException(status_code=401, detail="Se requiere access token")
    
    # Verificar que el barrio esté activo (excepto superadmin)
    if payload.get("rol") != "superadmin" and payload.get("barrio_id"):
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT activo FROM barrios WHERE id = %s", (payload["barrio_id"],))
        barrio = cur.fetchone()
        cur.close()
        conn.close()
        if not barrio or not barrio["activo"]:
            raise HTTPException(status_code=403, detail="Tu barrio está suspendido. Contacta al administrador.")
    
    return payload


def require_rol(*roles):
    def checker(usuario: dict = Depends(get_usuario_actual)):
        if usuario["rol"] not in roles:
            raise HTTPException(status_code=403, detail="No tienes permiso para esta acción")
        return usuario
    return checker

# ──────────────────────────────────────────
# ENDPOINTS PÚBLICOS
# ──────────────────────────────────────────

@app.get("/")
def inicio():
    return {"mensaje": "Servidor App Alarma funcionando", "version": "2.0"}


@app.post("/auth/login")
def login(data: LoginRequest):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM usuarios WHERE email = %s AND activo = TRUE", (data.email,))
    usuario = cur.fetchone()

    if not usuario or not bcrypt.checkpw(data.password.encode(), usuario["password_hash"].encode()):
        cur.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    # Verificar que el barrio esté activo (excepto superadmin que no pertenece a ningún barrio)
    if usuario["rol"] != "superadmin" and usuario["barrio_id"]:
        cur.execute("SELECT activo FROM barrios WHERE id = %s", (usuario["barrio_id"],))
        barrio = cur.fetchone()
        if not barrio or not barrio["activo"]:
            cur.close()
            conn.close()
            raise HTTPException(status_code=403, detail="Tu barrio está suspendido. Contacta al administrador.")
        
    # Crear tokens
    access_token = crear_access_token(usuario["id"], usuario["barrio_id"], usuario["rol"])
    refresh_token, expira = crear_refresh_token(usuario["id"], usuario["barrio_id"], usuario["rol"])

    # Guardar refresh token en base de datos
    cur.execute("""
        INSERT INTO tokens (usuario_id, barrio_id, tipo, token, expira_en)
        VALUES (%s, %s, 'refresh', %s, %s)
    """, (usuario["id"], usuario["barrio_id"], refresh_token, expira))

    conn.commit()
    cur.close()
    conn.close()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "rol": usuario["rol"],
        "nombre": usuario["nombre"],
        "barrio_id": usuario["barrio_id"],
        "casa": usuario["casa"]
    }


@app.post("/auth/refresh")
def refresh(data: RefreshRequest):
    payload = verificar_token(data.refresh_token)
    if payload.get("tipo") != "refresh":
        raise HTTPException(status_code=401, detail="Se requiere refresh token")

    conn = get_db()
    cur = conn.cursor()

    # Verificar que el refresh token existe en la base de datos (no fue revocado)
    cur.execute("""
        SELECT id FROM tokens
        WHERE token = %s AND tipo = 'refresh' AND expira_en > NOW()
    """, (data.refresh_token,))
    token_db = cur.fetchone()

    if not token_db:
        cur.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Sesión revocada o expirada. Inicia sesión de nuevo.")

    # Emitir nuevo access token
    nuevo_access = crear_access_token(
        int(payload["sub"]),
        payload["barrio_id"],
        payload["rol"]
    )

    cur.close()
    conn.close()
    return {"access_token": nuevo_access}


# ──────────────────────────────────────────
# ENDPOINTS SUPERADMIN
# ──────────────────────────────────────────

@app.post("/admin/barrios")
def crear_barrio(data: CrearBarrioRequest, usuario: dict = Depends(require_rol("superadmin"))):
    conn = get_db()
    cur = conn.cursor()

    # Generar código único para el barrio
    import random, string
    codigo = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

    # Crear el barrio
    cur.execute("""
        INSERT INTO barrios (nombre, direccion, ciudad, codigo_unico)
        VALUES (%s, %s, %s, %s) RETURNING id
    """, (data.nombre, data.direccion, data.ciudad, codigo))
    barrio_id = cur.fetchone()["id"]

    # Crear el admin_barrio
    password_hash = bcrypt.hashpw(data.password_admin.encode(), bcrypt.gensalt()).decode()
    cur.execute("""
        INSERT INTO usuarios (barrio_id, nombre, email, telefono, password_hash, rol)
        VALUES (%s, %s, %s, %s, %s, 'admin_barrio') RETURNING id
    """, (barrio_id, data.nombre_admin, data.email_admin, data.telefono_admin, password_hash))

    conn.commit()
    cur.close()
    conn.close()

    return {
        "mensaje": "Barrio creado exitosamente",
        "barrio_id": barrio_id,
        "codigo_unico": codigo,
        "admin_email": data.email_admin,
        "admin_password": data.password_admin
    }


@app.get("/admin/barrios")
def listar_barrios(usuario: dict = Depends(require_rol("superadmin"))):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT b.*,
               COUNT(DISTINCT u.id) FILTER (WHERE u.rol = 'vecino') as total_vecinos,
               (SELECT nombre FROM usuarios WHERE barrio_id = b.id AND rol = 'admin_barrio' LIMIT 1) as admin_nombre,
               (SELECT email FROM usuarios WHERE barrio_id = b.id AND rol = 'admin_barrio' LIMIT 1) as admin_email,
               (SELECT COUNT(*) FROM alertas WHERE barrio_id = b.id) as total_alertas
        FROM barrios b
        LEFT JOIN usuarios u ON u.barrio_id = b.id
        GROUP BY b.id
        ORDER BY b.creado_en DESC
    """)
    barrios = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(b) for b in barrios]

@app.put("/admin/barrios/{barrio_id}/pausar")
def pausar_barrio(barrio_id: int, usuario: dict = Depends(require_rol("superadmin"))):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE barrios SET activo = FALSE WHERE id = %s", (barrio_id,))
    # Invalidar todos los refresh tokens del barrio
    cur.execute("""
        DELETE FROM tokens 
        WHERE tipo = 'refresh' AND usuario_id IN (
            SELECT id FROM usuarios WHERE barrio_id = %s
        )
    """, (barrio_id,))
    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Barrio pausado. Los usuarios no podrán iniciar sesión."}


@app.put("/admin/barrios/{barrio_id}/reactivar")
def reactivar_barrio(barrio_id: int, usuario: dict = Depends(require_rol("superadmin"))):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE barrios SET activo = TRUE WHERE id = %s", (barrio_id,))
    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Barrio reactivado"}


@app.delete("/admin/barrios/{barrio_id}")
def eliminar_barrio(barrio_id: int, usuario: dict = Depends(require_rol("superadmin"))):
    conn = get_db()
    cur = conn.cursor()
    
    # Borrar en orden por las foreign keys
    cur.execute("DELETE FROM tokens WHERE barrio_id = %s", (barrio_id,))
    cur.execute("DELETE FROM alertas WHERE barrio_id = %s", (barrio_id,))
    cur.execute("UPDATE codigos_activacion SET barrio_id = NULL WHERE barrio_id = %s", (barrio_id,))
    cur.execute("DELETE FROM usuarios WHERE barrio_id = %s", (barrio_id,))
    cur.execute("DELETE FROM barrios WHERE id = %s", (barrio_id,))
    
    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Barrio eliminado completamente"}

@app.post("/admin/revocar-sesion")
def revocar_sesion(data: RevocarSesionRequest, usuario: dict = Depends(require_rol("superadmin", "admin_barrio"))):
    conn = get_db()
    cur = conn.cursor()

    # Si es admin_barrio, verificar que el usuario pertenece a su barrio
    if usuario["rol"] == "admin_barrio":
        cur.execute("SELECT barrio_id FROM usuarios WHERE id = %s", (data.usuario_id,))
        target = cur.fetchone()
        if not target or target["barrio_id"] != usuario["barrio_id"]:
            cur.close()
            conn.close()
            raise HTTPException(status_code=403, detail="No puedes revocar sesiones fuera de tu barrio")

    cur.execute("DELETE FROM tokens WHERE usuario_id = %s AND tipo = 'refresh'", (data.usuario_id,))
    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Sesión revocada. El usuario deberá iniciar sesión de nuevo."}
# ──────────────────────────────────────────
# CÓDIGOS DE ACTIVACIÓN
# ──────────────────────────────────────────

@app.post("/admin/codigos-activacion")
def generar_codigo_activacion(
    data: CrearCodigoRequest,
    usuario: dict = Depends(require_rol("superadmin"))
):
    import random, string
    # Formato: VINK-XXXX-XXXX
    parte1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    parte2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    codigo = f"VINK-{parte1}-{parte2}"

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO codigos_activacion (codigo, creado_por, notas)
        VALUES (%s, %s, %s) RETURNING id, codigo, creado_en
    """, (codigo, int(usuario["sub"]), data.notas))
    nuevo = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return {
        "mensaje": "Código generado",
        "codigo": nuevo["codigo"],
        "id": nuevo["id"]
    }


@app.get("/admin/codigos-activacion")
def listar_codigos_activacion(usuario: dict = Depends(require_rol("superadmin"))):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT c.id, c.codigo, c.usado, c.usado_en, c.notas, c.creado_en,
               b.nombre as barrio_nombre
        FROM codigos_activacion c
        LEFT JOIN barrios b ON b.id = c.barrio_id
        ORDER BY c.creado_en DESC
    """)
    codigos = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(c) for c in codigos]


@app.post("/auth/activar-barrio")
def activar_barrio(data: ActivarBarrioRequest):
    conn = get_db()
    cur = conn.cursor()

    # Verificar código
    cur.execute("""
        SELECT id, usado FROM codigos_activacion WHERE codigo = %s
    """, (data.codigo.strip().upper(),))
    codigo_db = cur.fetchone()

    if not codigo_db:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Código de activación inválido")
    if codigo_db["usado"]:
        cur.close()
        conn.close()
        raise HTTPException(status_code=403, detail="Este código ya fue utilizado")

    # Verificar que el email no exista
    cur.execute("SELECT id FROM usuarios WHERE email = %s", (data.email_admin,))
    if cur.fetchone():
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Este correo ya está registrado")

    # Generar código único del barrio para invitaciones
    import random, string
    codigo_barrio = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

    # Crear el barrio
    cur.execute("""
        INSERT INTO barrios (nombre, direccion, ciudad, codigo_unico)
        VALUES (%s, %s, %s, %s) RETURNING id
    """, (data.nombre_barrio, data.direccion, data.ciudad, codigo_barrio))
    barrio_id = cur.fetchone()["id"]

    # Crear el admin del barrio
    password_hash = bcrypt.hashpw(data.password_admin.encode(), bcrypt.gensalt()).decode()
    cur.execute("""
        INSERT INTO usuarios (barrio_id, nombre, email, telefono, password_hash, rol)
        VALUES (%s, %s, %s, %s, %s, 'admin_barrio') RETURNING id
    """, (barrio_id, data.nombre_admin, data.email_admin, data.telefono_admin, password_hash))

    # Marcar código como usado
    cur.execute("""
        UPDATE codigos_activacion 
        SET usado = TRUE, usado_en = NOW(), barrio_id = %s
        WHERE id = %s
    """, (barrio_id, codigo_db["id"]))

    conn.commit()
    cur.close()
    conn.close()

    return {
        "mensaje": "Barrio activado exitosamente",
        "barrio_id": barrio_id,
        "codigo_invitacion": codigo_barrio
    }

# ──────────────────────────────────────────
# ENDPOINTS ADMIN_BARRIO
# ──────────────────────────────────────────

@app.get("/barrio/vecinos")
def listar_vecinos(usuario: dict = Depends(require_rol("admin_barrio", "superadmin", "vecino"))):
    conn = get_db()
    cur = conn.cursor()
    barrio_id = usuario["barrio_id"]
    cur.execute("""
        SELECT id, nombre, email, telefono, casa, activo, creado_en
        FROM usuarios
        WHERE barrio_id = %s AND rol = 'vecino'
        ORDER BY casa
    """, (barrio_id,))
    vecinos = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(v) for v in vecinos]

@app.get("/barrio/vecinos")
def listar_vecinos(usuario: dict = Depends(require_rol("admin_barrio", "superadmin"))):
    conn = get_db()
    cur = conn.cursor()
    barrio_id = usuario["barrio_id"]
    cur.execute("""
        SELECT id, nombre, email, telefono, casa, activo, creado_en
        FROM usuarios
        WHERE barrio_id = %s AND rol = 'vecino'
        ORDER BY casa
    """, (barrio_id,))
    vecinos = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(v) for v in vecinos]


@app.delete("/barrio/vecinos/{vecino_id}")
def eliminar_vecino(vecino_id: int, usuario: dict = Depends(require_rol("admin_barrio", "superadmin"))):
    conn = get_db()
    cur = conn.cursor()
    
    # Verificar que el vecino pertenece al barrio del admin
    cur.execute("""
        SELECT id FROM usuarios
        WHERE id = %s AND barrio_id = %s AND rol = 'vecino'
    """, (vecino_id, usuario["barrio_id"]))
    if not cur.fetchone():
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Vecino no encontrado")
    
    # Conservar las alertas pero quitar la referencia al usuario
    cur.execute("UPDATE alertas SET usuario_id = NULL WHERE usuario_id = %s", (vecino_id,))
    
    # Borrar tokens del vecino
    cur.execute("DELETE FROM tokens WHERE usuario_id = %s", (vecino_id,))
    
    # Borrar el vecino
    cur.execute("DELETE FROM usuarios WHERE id = %s", (vecino_id,))
    
    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Vecino eliminado"}
class RegistroPorCodigoRequest(BaseModel):
    codigo_unico: str
    nombre: str
    email: EmailStr
    telefono: Optional[str] = None
    casa: str
    password: str


@app.post("/auth/registro-codigo")
def registro_por_codigo(data: RegistroPorCodigoRequest):
    conn = get_db()
    cur = conn.cursor()

    # Buscar barrio por código
    cur.execute("SELECT id, activo FROM barrios WHERE codigo_unico = %s", (data.codigo_unico.upper().strip(),))
    barrio = cur.fetchone()
    if not barrio:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Código de invitación inválido")
    if not barrio["activo"]:
        cur.close()
        conn.close()
        raise HTTPException(status_code=403, detail="El barrio no está activo")

    # Verificar que el email no exista
    cur.execute("SELECT id FROM usuarios WHERE email = %s", (data.email,))
    if cur.fetchone():
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Este correo ya está registrado")

    # Crear usuario
    password_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    cur.execute("""
        INSERT INTO usuarios (barrio_id, nombre, email, telefono, casa, password_hash, rol)
        VALUES (%s, %s, %s, %s, %s, %s, 'vecino') RETURNING id
    """, (barrio["id"], data.nombre, data.email, data.telefono, data.casa, password_hash))
    vecino_id = cur.fetchone()["id"]
    conn.commit()
    cur.close()
    conn.close()

    return {"mensaje": "Vecino registrado exitosamente", "vecino_id": vecino_id}


class ResetPasswordRequest(BaseModel):
    nueva_password: str


@app.put("/barrio/vecinos/{vecino_id}/reset-password")
def reset_password(
    vecino_id: int,
    data: ResetPasswordRequest,
    usuario: dict = Depends(require_rol("admin_barrio", "superadmin"))
):
    conn = get_db()
    cur = conn.cursor()

    # Verificar que el vecino pertenece al barrio del admin
    cur.execute("""
        SELECT id FROM usuarios
        WHERE id = %s AND barrio_id = %s AND rol = 'vecino'
    """, (vecino_id, usuario["barrio_id"]))
    if not cur.fetchone():
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Vecino no encontrado")

    password_hash = bcrypt.hashpw(data.nueva_password.encode(), bcrypt.gensalt()).decode()
    cur.execute("UPDATE usuarios SET password_hash = %s WHERE id = %s", (password_hash, vecino_id))

    # Invalidar refresh tokens del vecino para forzar nuevo login
    cur.execute("DELETE FROM tokens WHERE usuario_id = %s AND tipo = 'refresh'", (vecino_id,))

    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Contraseña actualizada correctamente"}
# ──────────────────────────────────────────
# ENDPOINTS VECINOS (y admin)
# ──────────────────────────────────────────

@app.post("/tokens/fcm")
def registrar_token_fcm(data: TokenFCMRequest, usuario: dict = Depends(get_usuario_actual)):
    conn = get_db()
    cur = conn.cursor()

    # Evitar duplicados: borrar token anterior del mismo usuario si existía
    cur.execute("""
        DELETE FROM tokens WHERE usuario_id = %s AND tipo = 'fcm'
    """, (int(usuario["sub"]),))

    cur.execute("""
        INSERT INTO tokens (usuario_id, barrio_id, tipo, token)
        VALUES (%s, %s, 'fcm', %s)
    """, (int(usuario["sub"]), usuario["barrio_id"], data.token))

    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Token FCM registrado"}


@app.post("/alertas")
def crear_alerta(data: AlertaRequest, usuario: dict = Depends(get_usuario_actual)):
    conn = get_db()
    cur = conn.cursor()

    barrio_id = usuario["barrio_id"]
    hora = datetime.now().strftime("%H:%M:%S")

    # Obtener datos del usuario
    cur.execute("SELECT nombre, casa FROM usuarios WHERE id = %s", (int(usuario["sub"]),))
    user_data = cur.fetchone()

    cur.execute("""
        INSERT INTO alertas (barrio_id, usuario_id, casa, vecino, tipo, descripcion, hora)
        VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *
    """, (
        barrio_id,
        int(usuario["sub"]),
        user_data["casa"],
        user_data["nombre"],
        data.tipo,
        data.descripcion,
        hora
    ))
    nueva_alerta = dict(cur.fetchone())

    # Obtener todos los tokens FCM del mismo barrio
    cur.execute("""
        SELECT t.token FROM tokens t
        JOIN usuarios u ON u.id = t.usuario_id
        WHERE t.tipo = 'fcm' AND t.barrio_id = %s AND u.activo = TRUE
    """, (barrio_id,))
    tokens_fcm = cur.fetchall()

    conn.commit()
    cur.close()
    conn.close()

    # Enviar notificación push a todos los vecinos del barrio
    tipo_labels = {
        "robo": "🚨 ALERTA DE ROBO",
        "sospechoso": "👁️ PERSONA SOSPECHOSA",
        "incendio": "🔥 ALERTA DE INCENDIO",
        "emergencia": "🆘 EMERGENCIA",
    }
    titulo = tipo_labels.get(data.tipo, "⚠️ ALERTA COMUNAL")

    for row in tokens_fcm:
        try:
            message = messaging.Message(
                notification=messaging.Notification(
                    title=titulo,
                    body=f"{user_data['nombre']} - {user_data['casa']}",
                ),
                data={
                    "tipo": data.tipo,
                    "casa": user_data["casa"] or "",
                    "vecino": user_data["nombre"],
                    "alerta_id": str(nueva_alerta["id"]),
                },
                token=row["token"],
            )
            messaging.send(message)
        except Exception as e:
            print(f"Error enviando notificación: {e}")

    return {"mensaje": "Alerta creada y vecinos notificados", "alerta": nueva_alerta}


@app.get("/alertas")
def obtener_alertas(usuario: dict = Depends(get_usuario_actual)):
    conn = get_db()
    cur = conn.cursor()

    if usuario["rol"] == "superadmin":
        # Superadmin ve todo
        cur.execute("SELECT * FROM alertas ORDER BY creado_en DESC LIMIT 100")
    else:
        # Vecinos y admins ven solo su barrio
        cur.execute("""
            SELECT * FROM alertas WHERE barrio_id = %s
            ORDER BY creado_en DESC LIMIT 100
        """, (usuario["barrio_id"],))

    alertas = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(a) for a in alertas]


@app.put("/alertas/{alerta_id}/desactivar")
def desactivar_alerta(alerta_id: int, usuario: dict = Depends(require_rol("admin_barrio", "superadmin"))):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        DELETE FROM alertas
        WHERE id = %s AND barrio_id = %s
    """, (alerta_id, usuario["barrio_id"]))
    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Alerta eliminada"}


@app.get("/auth/me")
def mi_perfil(usuario: dict = Depends(get_usuario_actual)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.id, u.nombre, u.email, u.telefono, u.casa, u.rol, u.creado_en,
               b.nombre as barrio_nombre, b.ciudad, b.codigo_unico
        FROM usuarios u
        LEFT JOIN barrios b ON b.id = u.barrio_id
        WHERE u.id = %s
    """, (int(usuario["sub"]),))
    perfil = cur.fetchone()
    cur.close()
    conn.close()
    return dict(perfil)


@app.get("/barrio/info")
def info_barrio(usuario: dict = Depends(require_rol("admin_barrio", "superadmin", "vecino"))):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT nombre, direccion, ciudad, codigo_unico, 
               telefono_vigilante, telefono_presidente 
        FROM barrios WHERE id = %s
    """, (usuario["barrio_id"],))
    barrio = cur.fetchone()
    cur.close()
    conn.close()
    return dict(barrio)

@app.put("/barrio/contactos")
def actualizar_contactos(
    datos: dict,
    usuario: dict = Depends(require_rol("admin_barrio", "superadmin"))
):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE barrios SET 
            telefono_vigilante = %s,
            telefono_presidente = %s
        WHERE id = %s
    """, (datos.get("telefono_vigilante"), datos.get("telefono_presidente"), usuario["barrio_id"]))
    conn.commit()
    cur.close()
    conn.close()
    return {"mensaje": "Contactos actualizados"}