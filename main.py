from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, messaging

app = FastAPI(title="App Alarma API")

import os
import json

# Inicializar Firebase desde variable de entorno
google_credentials = os.environ.get("GOOGLE_CREDENTIALS")
if google_credentials:
    cred_dict = json.loads(google_credentials)
    cred = credentials.Certificate(cred_dict)
else:
    cred = credentials.Certificate("serviceAccount.json")
firebase_admin.initialize_app(cred)
# Base de datos temporal en memoria
alertas = []
tokens_vecinos = []  # Aquí se guardan los tokens de los celulares

class Alerta(BaseModel):
    casa: str
    vecino: str
    tipo: str
    barrio: str

class Token(BaseModel):
    token: str

@app.get("/")
def inicio():
    return {"mensaje": "Servidor App Alarma funcionando"}

@app.post("/registrar-token")
def registrar_token(data: Token):
    if data.token not in tokens_vecinos:
        tokens_vecinos.append(data.token)
    return {"mensaje": "Token registrado", "total": len(tokens_vecinos)}

@app.post("/alertas")
def crear_alerta(alerta: Alerta):
    nueva = {
        "id": len(alertas) + 1,
        "casa": alerta.casa,
        "vecino": alerta.vecino,
        "tipo": alerta.tipo,
        "barrio": alerta.barrio,
        "hora": datetime.now().strftime("%H:%M:%S"),
        "activa": True
    }
    alertas.append(nueva)

    # Enviar notificación a todos los vecinos
    for token in tokens_vecinos:
        try:
            message = messaging.Message(
                notification=messaging.Notification(
                    title="🚨 ALERTA DE ROBO",
                    body=f"{alerta.vecino} - {alerta.casa}",
                ),
                data={
                    "casa": alerta.casa,
                    "vecino": alerta.vecino,
                    "tipo": alerta.tipo,
                },
                token=token,
            )
            messaging.send(message)
        except Exception as e:
            print(f"Error enviando notificación: {e}")

    return {"mensaje": "Alerta creada y vecinos notificados", "alerta": nueva}

@app.get("/alertas")
def obtener_alertas():
    return alertas

@app.put("/alertas/{id}/desactivar")
def desactivar_alerta(id: int):
    for alerta in alertas:
        if alerta["id"] == id:
            alerta["activa"] = False
            return {"mensaje": "Alerta desactivada"}
    return {"error": "Alerta no encontrada"}