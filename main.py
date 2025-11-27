from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.security import HTTPBearer
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Optional, List
from uuid import UUID, uuid4
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import io
import random
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import List
from fastapi import Depends
from sqlalchemy.orm import Session
from datetime import datetime
from pydantic import BaseModel
from database import SessionLocal, engine
from models import Base, Customer as CustomerORM, Order as OrderORM, OrderItem as OrderItemORM, Tracking as TrackingORM, DeliveryPerson as DeliveryPersonORM

# Crear tablas si no existen
Base.metadata.create_all(bind=engine)

# Dependencia BD
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------------------
# CORS + App Config
# ---------------------------
from fastapi.middleware.cors import CORSMiddleware

APP_TITLE = "API Pollos Abrosos"
API_PREFIX = "/api/pollosabroso"

app = FastAPI(
    title=APP_TITLE,
    description="Implementación Monolítica de la arquitectura de servicios.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # permitir cualquier origen (solo para practicar)
    allow_credentials=False,  # IMPORTANTE: en False para que '*' funcione
    allow_methods=["*"],
    allow_headers=["*"],
)




# --- LIBRERÍAS DE SEGURIDAD ---
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- 1. MODELOS DE DATOS (DTOs Y ENTIDADES DE TUS 27 DIAGRAMAS) ---

# --- Modelo de Respuesta Genérico ---
class Response(BaseModel):
    statusCode: int = 200
    message: str = "OK"
    data: Optional[dict | list] = None

# --- Diagrama 01: Registro Clientes ---
class CustomerRegistrationInput(BaseModel):
    name: str
    email: str
    phone: str
    password: str

class Customer(BaseModel): 
    id: UUID
    name: str
    email: str
    phone: str
    emailVerified: bool = False
    createdAt: datetime

    class Config:
        from_attributes = True




# --- Diagrama 02: Validacion Correo ---
class EmailValidationInput(BaseModel):
    userId: UUID
    token: str

class EmailValidationToken(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    token: str
    expiresAt: datetime
    validatedAt: Optional[datetime] = None

# --- Diagrama 03: Cuenta Usuario ---
class CustomerProfile(BaseModel):
    id: UUID
    name: str
    email: str
    phone: Optional[str] = None
    emailVerified: bool
    points: int = 0         # 👈 NUEVO CAMPO

    class Config:
        from_attributes = True    # o orm_mode = True


class UserAccountInput(BaseModel):
    status: str # ej. "activo", "inactivo"

class UserAccount(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    status: str
    createdAt: datetime = Field(default_factory=datetime.now)
    updatedAt: Optional[datetime] = None

# --- Diagrama 04: Inicio y Cierre de Sesion ---
class LoginInput(BaseModel):
    email: str
    password: str

class Session(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    token: str
    createdAt: datetime = Field(default_factory=datetime.now)
    expiresAt: datetime
############################
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

# --- Diagrama 05: Recuperar Contrasena --- 
class PasswordRecoveryInput(BaseModel):
    email: str

class RecoveryToken(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    token: str
    expiresAt: datetime
    usedAt: Optional[datetime] = None

# --- Diagrama 06: Gestion Perfil Usuario ---
class UserProfileInput(BaseModel):
    name: str
    address: str
    phone: str

class UserProfile(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    name: str
    address: str
    phone: str
    updatedAt: datetime = Field(default_factory=datetime.now)

# --- Diagrama 07: Personalizacion de Pedidos ---
class OrderSummary(BaseModel):
    id: str
    date: datetime
    description: str
    itemsCount: int
    pointsEarned: int

    class Config:
        from_attributes = True

class OrderPersonalizationInput(BaseModel):
    # userId se obtendrá del token
    spiceLevel: str
    extras: List[str]
    notes: str

class OrderPreference(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    spiceLevel: str
    extras: List[str]
    notes: str

# --- Diagrama 08: Filtrar y Buscar ---
class SearchFilterInput(BaseModel):
    keywords: Optional[str] = None
    category: Optional[str] = None
    minPrice: Optional[Decimal] = None
    maxPrice: Optional[Decimal] = None
    sortBy: Optional[str] = None

# --- Diagrama 09: Registro de Pedidos ---
class OrderItemInput(BaseModel):
    productId: UUID
    quantity: int

class OrderInput(BaseModel):
    items: List[OrderItemInput]
    notes: Optional[str] = None

class Order(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    items: List[OrderItemInput]
    notes: Optional[str] = None
    status: str = "pendiente"
    createdAt: datetime = Field(default_factory=datetime.now)

# Lista para almacenar pedidos (simulado)
orders: List[Order] = []

# --- Diagrama 10: Integracion Pasarela de Pago ---
class PaymentGatewayInput(BaseModel):
    orderId: UUID
    amount: Decimal
    provider: str
    token: str # Token de la tarjeta

class PaymentGateway(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    provider: str
    transactionId: str
    status: str
    amount: Decimal

# --- Diagrama 11: Confirmacion Automatica de Pago ---
class PaymentConfirmationInput(BaseModel):
    orderId: UUID
    gatewayTransactionId: str

class Payment(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    orderId: UUID
    status: str
    authorizationCode: str
    confirmedAt: datetime = Field(default_factory=datetime.now)

# --- Diagrama 12: Generacion de Boletas Digitales ---
class DigitalInvoiceInput(BaseModel):
    orderId: UUID
    amount: Decimal

class Invoice(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    orderId: UUID
    number: str
    total: Decimal
    pdfUrl: str
    generatedAt: datetime = Field(default_factory=datetime.now)

# --- Diagrama 13: Envio de Boletas por Correo ---
class SendInvoiceEmailInput(BaseModel):
    invoiceId: UUID
    email: str

class InvoiceDispatch(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    invoiceId: UUID
    email: str
    sentAt: datetime = Field(default_factory=datetime.now)
    status: str

# --- Diagrama 14: Panel Control Cocina ---
class KitchenPanelInput(BaseModel):
    status: str # ej. "Pendiente", "EnPreparacion"

class KitchenTicket(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    orderId: UUID
    status: str
    startedAt: Optional[datetime] = None
    readyAt: Optional[datetime] = None

# --- Diagrama 15: Alertas de Tiempos de Coccion ---
class CookingTimeAlertInput(BaseModel):
    ticketId: UUID
    thresholdMinutes: int
class TrackingUpdateInput(BaseModel):
    orderId: UUID
    status: str  # ejemplo: "en ruta", "cerca", "entregado"

class CookingAlert(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    ticketId: UUID
    thresholdMinutes: int
    triggeredAt: datetime = Field(default_factory=datetime.now)

# --- Diagrama 16: Notificacion al Cliente ---
class CustomerNotificationInput(BaseModel):
    userId: UUID
    title: str
    message: str

class Notification(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    title: str
    message: str
    sentAt: datetime = Field(default_factory=datetime.now)

# --- Diagrama 17: Asignacion Automatica de Repartidores ---
class AutoDriverAssignmentInput(BaseModel):
    orderId: UUID

class Assignment(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    orderId: UUID
    driverId: UUID
    assignedAt: datetime = Field(default_factory=datetime.now)
    status: str

# --- Diagrama 18: Planificacion de Rutas ---
class RoutePlanningInput(BaseModel):
    date: datetime
    orders: List[UUID]

class RoutePlan(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    date: datetime
    stops: int
    optimizedBy: str
    createdAt: datetime = Field(default_factory=datetime.now)

# --- Diagrama 19: Panel de Repartidor ---
class CourierPanelInput(BaseModel):
    driverId: UUID

class CourierAssignmentView(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    driverId: UUID
    orderId: UUID
    status: str
    updatedAt: datetime = Field(default_factory=datetime.now)

# --- Diagrama 20: Seguimiento del Pedido ---
class OrderTrackingInput(BaseModel):
    orderId: UUID

class Tracking(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    orderId: UUID
    status: str
    lat: Optional[float] = None
    lng: Optional[float] = None
    updatedAt: datetime = Field(default_factory=datetime.now)



# --- Diagrama 21: Acumular Puntos por Compras ---
class PointsUpdate(BaseModel):
    amount: int

class LoyaltyPointsInput(BaseModel):
    userId: UUID
    orderId: UUID
    points: int

class LoyaltyPoints(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    orderId: UUID
    points: int
    accruedAt: datetime = Field(default_factory=datetime.now)

# --- Diagrama 22: Canjear Cupones de Descuento ---
class RedeemCouponInput(BaseModel):
    # userId se obtendrá del token
    code: str

class CouponRedemption(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    code: str
    discountPct: int
    redeemedAt: datetime = Field(default_factory=datetime.now)

# --- Diagrama 23: Recibir Promociones Personalizadas ---
class PersonalizedPromotionInput(BaseModel):
    segment: str
    title: str
    discountPct: int

class Promotion(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    title: str
    discountPct: int
    segment: str
    sentAt: datetime = Field(default_factory=datetime.now)

# --- Diagrama 24: Recordatorio de Promociones ---
class PromotionReminderInput(BaseModel):
    userId: UUID
    title: str
    reminderAt: datetime
    channel: str # "email", "sms"

class PromotionReminder(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    title: str
    reminderAt: datetime
    channel: str

# --- Diagrama 25: Formularios ---
class FormSubmissionInput(BaseModel):
    # userId se obtendrá del token
    type: str
    content: str

class FormSubmission(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    userId: UUID
    type: str
    content: str
    createdAt: datetime = Field(default_factory=datetime.now)

# --- Diagrama 26: Integracion Sistema de Datos ---
class DataSystemIntegrationInput(BaseModel):
    source: str
    records: int

class IntegrationJob(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    source: str
    status: str
    syncedAt: datetime = Field(default_factory=datetime.now)
    records: int


# --- 2. CONFIGURACIÓN DE SEGURIDAD ---
# --- 2. CONFIGURACIÓN DE SEGURIDAD ---
SECRET_KEY = "clave-secreta-pollos-abrosos"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = HTTPBearer()


# --- 3. FUNCIONES HELPER DE SEGURIDAD ---
def verificar_contraseña(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def hashear_contraseña(password: str) -> str:
    return pwd_context.hash(password)

def crear_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# --- helper BD ---
def get_customer_by_email(db: Session, email: str) -> Optional[CustomerORM]:
    return db.query(CustomerORM).filter(CustomerORM.email == email).first()


def autenticar_cliente(db: Session, email: str, password: str) -> Optional[CustomerORM]:
    user = get_customer_by_email(db, email)
    if not user:
        return None
    if not verificar_contraseña(password, user.hashed_password):
        return None
    return user


# --- Token especial para verificación de correo --- 
def crear_token_verificacion_email(email: str) -> str:
    """
    Crea un JWT de corta duración para verificar correo.
    """
    datos = {
        "sub": email,          # sujeto = correo
        "scope": "email_verify"
    }
    return crear_access_token(
        datos,
        expires_delta=timedelta(minutes=30)
    )



# --- 4. "BASE DE DATOS" (temporal, en memoria) ---
db_customers: List[Customer] = []
email_verification_tokens: dict[UUID, str] = {}
password_recovery_codes: dict[str, str] = {}
db_orders: List[Order] = []
db_payments: List[Payment] = []
db_invoices: List[Invoice] = []
db_kitchen_tickets: List[KitchenTicket] = []
db_trackings: List[Tracking] = []
db_loyalty_points: List[LoyaltyPoints] = []
# ... (y así para las 27 entidades)


# --- 5. FUNCIONES DE AUTENTICACIÓN Y BBDD ---
def get_customer_by_id(db: Session, customer_id: str):
    return db.query(CustomerORM).filter(CustomerORM.id == customer_id).first()

def get_customer_by_email(db: Session, email: str):
    return db.query(CustomerORM).filter(CustomerORM.email == email).first()

def authenticate_customer(db: Session, email: str, password: str):
    """
    Autentica al cliente contra la BD MySQL.
    Retorna el objeto CustomerORM si las credenciales son correctas,
    o None en caso contrario.
    """
    user = get_customer_by_email(db, email)
    if not user:
        return None
    # Verificar contraseña con bcrypt
    if not pwd_context.verify(password, user.hashed_password):
        return None
    return user




def get_order_for_customer(db: Session, order_id: str, customer_id: str):
    """
    Busca un pedido por id que pertenezca al cliente indicado.
    """
    return db.query(OrderORM).filter(
        OrderORM.id == order_id,
        OrderORM.user_id == customer_id
    ).first()


async def get_current_customer(
    token: HTTPAuthorizationCredentials = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    """
    Obtiene el cliente actual a partir del JWT enviado en el Authorization header.
    Funciona con HTTPBearer (token.credentials) y busca al usuario en MySQL.
    """
    credentials_exception = HTTPException(
        status_code=401,
        detail="No se pudieron validar las credenciales (Token inválido)",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Extraer el string real del token desde HTTPAuthorizationCredentials
        token_str = token.credentials

        # Decodificar el JWT
        payload = jwt.decode(token_str, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")

        if user_id is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    # Buscar usuario por ID en MySQL
    user = db.query(CustomerORM).filter(CustomerORM.id == user_id).first()

    if user is None:
        raise credentials_exception

    return user




# Prefijo global para todos los endpoints
API_PREFIX = "/api/pollosabroso"


# --- 7. ENDPOINTS (API) ---

@app.get("/")
def read_root():
    return {"mensaje": "API Gateway de Pollos Abrosos funcionando. Ve a /docs para ver los endpoints."}


# --- Servicio: Auth (Diagramas 02, 04, 05) ---

@app.post(f"{API_PREFIX}/sesion/inicio", response_model=TokenResponse, tags=["AuthService"])
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    (Diagrama 04) Iniciar Sesión (versión MySQL).
    Usa 'username' (email) y 'password'.
    """
    # Autenticar contra MySQL
    customer = authenticate_customer(db, form_data.username, form_data.password)
    if not customer:
        raise HTTPException(
            status_code=401,
            detail="Email o contraseña incorrecta",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # Aquí el "sub" DEBE ser el id del usuario (como pide JWT)
    access_token = crear_access_token(
        data={"sub": str(customer.id)},
        expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


@app.post(f"{API_PREFIX}/auth/login", response_model=Token, tags=["Auth"])
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Login de cliente.
    Recibe username (email) y password vía formulario x-www-form-urlencoded.
    Devuelve un access_token JWT.
    """
    user = autenticar_cliente(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Correo o contraseña incorrectos")

    # OJO: aquí usamos tu propia función crear_access_token
    access_token = crear_access_token(data={"sub": user.id})


    return Token(access_token=access_token)

# --- Verificación de correo ---
@app.get(f"{API_PREFIX}/auth/verify-email", tags=["Auth"])
def verify_email(token: str, db: Session = Depends(get_db)):
    """
    Endpoint que se llama desde el link enviado por correo.
    Marca el correo del usuario como verificado.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        scope = payload.get("scope")
        email = payload.get("sub")

        if scope != "email_verify" or email is None:
            raise HTTPException(status_code=400, detail="Token de verificación inválido")

    except JWTError:
        raise HTTPException(status_code=400, detail="Token inválido o expirado")

    user = get_customer_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # Marcar como verificado
    user.email_verified = True
    db.commit()

    return {"message": "Correo verificado correctamente"}




@app.post(f"{API_PREFIX}/sesion/recuperar", tags=["AuthService"])
def recover_password(input: PasswordRecoveryInput):
    """(Diagrama 05) Recuperar Contraseña"""
    # 1. Verificar si existe el usuario
    customer = get_customer_by_email(input.email)
    if not customer:
        raise HTTPException(status_code=404, detail="No existe un usuario con ese correo")
    
    # 2. Generar un código
    import random
    code = str(random.randint(100000, 999999))

    # 3. Guardar el código en memoria
    password_recovery_codes[input.email] = code

    # 4. "Enviar" el código (simulado)
    print(f"[DEBUG] Código de recuperación para {input.email}: {code}")

    # 5. Respuesta hacia Swagger
    return {"message": "Se envió un código de verificación al correo."}


# --- Confirmar recuperación de contraseña (validar token) ---
class PasswordRecoveryConfirmInput(BaseModel):
    userId: UUID
    token: str

@app.post(f"{API_PREFIX}/sesion/recuperar/validar", response_model=Response, tags=["AuthService"])
def confirm_password_recovery(input: PasswordRecoveryConfirmInput):
    """ (Diagrama 05) Confirmar código de recuperación """

    # Buscar el token del usuario
    for email, stored_code in password_recovery_codes.items():
        customer = get_customer_by_email(email)
        if customer and customer.id == input.userId and stored_code == input.token:

            print(f"[DEBUG] Código validado correctamente para usuario {input.userId}")

            # Marcar el código como usado (lo eliminamos)
            del password_recovery_codes[email]

            return Response(message="Código verificado correctamente")

    raise HTTPException(status_code=400, detail="El código no es válido")




@app.post(f"{API_PREFIX}/correo/validacion", response_model=EmailValidationToken, tags=["AuthService"])
def validate_email(input: EmailValidationInput):
    """
    (Diagrama 02) Validar Correo.
    Recibe userId y token, valida el código y marca el correo como verificado.
    """
    print(f"Validando token {input.token} para usuario {input.userId}")

    # 1) Buscar el cliente
    customer = next((c for c in db_customers if c.id == input.userId), None)
    if customer is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # 2) Ver si hay un código pendiente para ese usuario
    expected_code = email_verification_tokens.get(input.userId)
    if expected_code is None:
        raise HTTPException(status_code=400, detail="No hay un código pendiente para este usuario")

    # 3) Comparar el código
    if expected_code != input.token:
        raise HTTPException(status_code=400, detail="Código de verificación incorrecto")

    # 4) Marcar correo como verificado
    customer.emailVerified = True

    # 5) Borrar el código ya usado
    email_verification_tokens.pop(input.userId, None)

    # 6) Devolver el token de validación (Diagrama 02)
    validated_token = EmailValidationToken(
        userId=input.userId,
        token=input.token,
        expiresAt=datetime.now(),
        validatedAt=datetime.now()
    )
    return validated_token


# --- Servicio: User (Diagramas 01, 03, 06, 21, 22) ---

# --- Registro de clientes con link de verificación de correo ---
@app.post(f"{API_PREFIX}/clientes/registro", response_model=Customer, status_code=201, tags=["UserService"])
def register_customer(input: CustomerRegistrationInput, db: Session = Depends(get_db)):
    """
    (Diagrama 01) Registro de Clientes.
    Crea el cliente en MySQL y genera un LINK de verificación de correo (JWT).
    El link se imprime en consola como simulación del correo.
    """

    # 1) Validar email duplicado
    existing = get_customer_by_email(db, input.email)
    if existing:
        raise HTTPException(status_code=400, detail="El email ya está en uso")

    print(f"Registrando nuevo cliente: {input.name}")

    # 2) Hashear contraseña
    hashed_password = hashear_contraseña(input.password)

    # 3) Crear el cliente en BD
    new_customer = CustomerORM(
        name=input.name,
        email=input.email,
        phone=input.phone,
        hashed_password=hashed_password,
        email_verified=False
    )

    db.add(new_customer)
    db.commit()
    db.refresh(new_customer)


    # 4) Generar token JWT corto para verificación de email
    token_verificacion = crear_token_verificacion_email(new_customer.email)
    verify_url = f"http://127.0.0.1:8000{API_PREFIX}/auth/verify-email?token={token_verificacion}"

    # 5) MOSTRAR LINK EN CONSOLA (simula el correo)
    print(f"[DEBUG] Link para verificar correo de {new_customer.email}:")
    print(f"👉 {verify_url}")

    # 6) Devolver al cliente (igual que hacías antes)
    return Customer(
        id=new_customer.id,
        name=new_customer.name,
        email=new_customer.email,
        phone=new_customer.phone,
        hashed_password=new_customer.hashed_password,
        emailVerified=False
    )
# --- Perfil del cliente logueado ---
@app.get(f"{API_PREFIX}/clientes/me", response_model=CustomerProfile, tags=["UserService"])
def get_my_profile(current_customer: CustomerORM = Depends(get_current_customer)):
    return CustomerProfile(
        id=current_customer.id,
        name=current_customer.name,
        email=current_customer.email,
        phone=current_customer.phone,
        emailVerified=bool(current_customer.email_verified),
        points=current_customer.points,   # 👈 AQUÍ SUMAMOS LOS PUNTOS
    )




@app.put(f"{API_PREFIX}/cuenta/gestion", response_model=Response, tags=["UserService"])
def manage_account(input: UserAccountInput, current_customer: Customer = Depends(get_current_customer)):
    """
    (Diagrama 03) Gestionar Cuenta de Usuario (Ej. Activar/Desactivar).
    Endpoint protegido.
    """
    print(f"Usuario {current_customer.email} actualizando estado de cuenta a: {input.status}")
    # Lógica de BBDD (Simulada)
    return Response(message=f"Estado de cuenta actualizado")

@app.put(f"{API_PREFIX}/perfil/gestion", response_model=Response, tags=["UserService"])
def manage_profile(input: UserProfileInput, current_customer: Customer = Depends(get_current_customer)):
    """
    (Diagrama 06) Gestionar Perfil de Usuario.
    Endpoint protegido.
    """
    print(f"Usuario {current_customer.email} actualizando perfil.")
    # Lógica de BBDD (Simulada)
    current_customer.name = input.name
    current_customer.phone = input.phone
    # (En una BBDD real, aquí harías db.commit())
    return Response(message=f"Perfil actualizado para {current_customer.name}")

@app.post(f"{API_PREFIX}/clientes/me/puntos/acumular", tags=["UserService"])
def acumular_puntos(
    input: PointsUpdate,
    current_customer: CustomerORM = Depends(get_current_customer),
    db: Session = Depends(get_db)
):
    if input.amount <= 0:
        raise HTTPException(status_code=400, detail="La cantidad debe ser positiva.")

    current_customer.points += input.amount
    db.commit()
    db.refresh(current_customer)

    return {
        "message": f"Se sumaron {input.amount} puntos.",
        "points": current_customer.points
    }
@app.post(f"{API_PREFIX}/clientes/me/puntos/canjear", tags=["UserService"])
def canjear_puntos(
    input: PointsUpdate,
    current_customer: CustomerORM = Depends(get_current_customer),
    db: Session = Depends(get_db)
):
    if input.amount <= 0:
        raise HTTPException(status_code=400, detail="La cantidad debe ser positiva.")

    if current_customer.points < input.amount:
        raise HTTPException(status_code=400, detail="No tienes puntos suficientes para canjear.")

    current_customer.points -= input.amount
    db.commit()
    db.refresh(current_customer)

    return {
        "message": f"Se canjearon {input.amount} puntos.",
        "points": current_customer.points
    }

@app.get(f"{API_PREFIX}/clientes/me/pedidos", response_model=List[OrderSummary], tags=["PedidoService"])
def get_my_orders(
    current_customer: CustomerORM = Depends(get_current_customer),
    db: Session = Depends(get_db)
):
    """
    Devuelve los pedidos recientes del cliente actual.
    Se usa para la tabla 'Compras recientes'.
    """
    # 1) Obtener los pedidos del cliente (los 10 más recientes)
    orders = (
        db.query(OrderORM)
        .filter(OrderORM.user_id == current_customer.id)
        .order_by(OrderORM.created_at.desc())
        .limit(10)
        .all()
    )

    summaries: List[OrderSummary] = []

    for order in orders:
        # Buscar los items del pedido
        items = db.query(OrderItemORM).filter(OrderItemORM.order_id == order.id).all()

        total_unidades = sum(i.quantity for i in items)
        earned_points = total_unidades * 10  # misma regla que usamos en register_order

        # Podríamos armar una descripción simple
        if items:
            first_name = items[0].product_name
            if len(items) == 1:
                description = first_name
            else:
                description = f"{first_name} + {len(items)-1} ítem(s) más"
        else:
            description = "Pedido sin items"

        summaries.append(
            OrderSummary(
                id=str(order.id),
                date=order.created_at,
                description=description,
                itemsCount=total_unidades,
                pointsEarned=earned_points,
            )
        )

    return summaries


@app.post(f"{API_PREFIX}/cupones/canjear", response_model=Response, tags=["UserService"])
def redeem_coupon(input: RedeemCouponInput, current_customer: Customer = Depends(get_current_customer)):
    """
    (Diagrama 22) Canjear Cupón.
    Endpoint protegido.
    """
    print(f"Usuario {current_customer.email} intentando canjear cupón: {input.code}")
    # Lógica de BBDD (Simulada)
    return Response(message=f"Cupón canjeado exitosamente")

# --- Servicio: Pedido/Pago (Diagramas 07, 09, 10, 11) ---

@app.post(f"{API_PREFIX}/pedidos/personalizacion", response_model=Response, tags=["PedidoService"])
def set_order_personalization(
    input: OrderPersonalizationInput,
    current_customer: Customer = Depends(get_current_customer)
):
    """
    (Diagrama 07) Personalización de Pedidos.
    Endpoint protegido.
    """
    print(f"Guardando preferencias para {current_customer.email}: {input.notes}")

    return Response(
        statusCode=200,
        message="Preferencias guardadas",
        data={}
    )


# BD simulada:
orders: List[Order] = []


@app.post(f"{API_PREFIX}/pedidos/registro", response_model=Order, tags=["PedidoService"])
def register_order(
    order_input: OrderInput,
    current_customer: CustomerORM = Depends(get_current_customer),  # 👈 mejor usar el ORM
    db: Session = Depends(get_db)
):
    """
    (Diagrama 09) Registro de Pedidos.
    Versión MySQL adaptada a los modelos Pydantic + PUNTOS.
    """
    print(f"Registrando nuevo pedido para {current_customer.email}")

    # 1) Crear pedido en BD (total lo dejamos en 0 por ahora)
    new_order = OrderORM(
        user_id=current_customer.id,
        total=0  # porque tu modelo aún no incluye precio real
    )
    db.add(new_order)
    db.commit()
    db.refresh(new_order)

    # 2) Registrar items en la BD
    for item in order_input.items:
        db_item = OrderItemORM(
            order_id=new_order.id,
            product_name=str(item.productId),  # guardamos productId como texto
            quantity=item.quantity,
            price=0  # sin precio por ahora
        )
        db.add(db_item)

    db.commit()

    # 3) Crear tracking inicial
    tracking = TrackingORM(
        order_id=new_order.id,
        status="En preparación"
    )
    db.add(tracking)
    db.commit()
    db.refresh(tracking)

    # 4) 🔥 Calcular puntos ganados y sumarlos al cliente
    #    Regla simple: 10 puntos por cada unidad comprada
    total_unidades = sum(item.quantity for item in order_input.items)
    earned_points = total_unidades * 10

    current_customer.points += earned_points
    db.commit()
    db.refresh(current_customer)

    print(f"[PUNTOS] Pedido {new_order.id}: +{earned_points} puntos para {current_customer.email}. Total ahora: {current_customer.points}")

    # 5) Devolver el pedido según tu Pydantic Order
    return Order(
        id=new_order.id,
        userId=new_order.user_id,
        items=order_input.items,
        notes=order_input.notes,
        status=tracking.status,
        createdAt=new_order.created_at
    )

@app.get(f"{API_PREFIX}/pedidos/{{order_id}}", response_model=Order, tags=["PedidoService"])
def get_order_by_id(
    order_id: UUID,
    current_customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db)
):
    """
    (Diagrama 10) Obtener detalle de un pedido por ID.
    Solo permite ver pedidos del cliente autenticado.
    """
    # Buscar el pedido en BD verificando que sea del usuario logueado
    order_db = get_order_for_customer(db, str(order_id), str(current_customer.id))
    if not order_db:
        raise HTTPException(status_code=404, detail="Pedido no encontrado")

    # Reconstruir la lista de items según tu modelo Pydantic
    items_pydantic: List[OrderItemInput] = []
    for item in order_db.items:
        # product_name guarda el UUID en texto
        product_uuid = UUID(item.product_name)
        items_pydantic.append(
            OrderItemInput(
                productId=product_uuid,
                quantity=item.quantity
            )
        )

    # Estado desde tracking (o "pendiente" si no hay)
    status = order_db.tracking.status if order_db.tracking else "pendiente"

    # Devolver en el formato de tu modelo Order
    return Order(
        id=UUID(order_db.id),
        userId=UUID(order_db.user_id),
        items=items_pydantic,
        notes=None,  # por ahora no guardamos notes en BD
        status=status,
        createdAt=order_db.created_at
    )
@app.get(f"{API_PREFIX}/mis-pedidos", response_model=List[Order], tags=["PedidoService"])
def list_my_orders(
    current_customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db)
):
    """
    (Diagrama extra) Listar todos los pedidos del cliente autenticado.
    """
    # 1) Buscar todos los pedidos del usuario en BD
    orders_db = db.query(OrderORM).filter(
        OrderORM.user_id == str(current_customer.id)
    ).all()

    result: List[Order] = []

    for order_db in orders_db:
        # Reconstruir items Pydantic
        items_pydantic: List[OrderItemInput] = []
        for item in order_db.items:
            try:
                product_uuid = UUID(item.product_name)
            except:
                product_uuid = UUID("00000000-0000-0000-0000-000000000000")

            items_pydantic.append(
                OrderItemInput(
                    productId=product_uuid,
                    quantity=item.quantity
                )
            )

        # Estado desde tracking
        status = order_db.tracking.status if order_db.tracking else "pendiente"

        # Armar modelo Order
        result.append(
            Order(
                id=UUID(order_db.id),
                userId=UUID(order_db.user_id),
                items=items_pydantic,
                notes=None,
                status=status,
                createdAt=order_db.created_at
            )
        )

    return result




# -----------------------------
# PAYMENT SERVICE (Diagrama 10)
# -----------------------------

@app.post(f"{API_PREFIX}/pagos/pasarela", tags=["PaymentService"])
def process_payment(input: PaymentGatewayInput, current_customer: Customer = Depends(get_current_customer)):
    """
    (Diagrama 10) Integración Pasarela de Pago.
    Endpoint protegido.
    """
    print(f"[DEBUG] Intentando procesar pago para orden {input.orderId} y usuario {current_customer.id}")

    # Buscar el pedido del cliente autenticado
    order = next(
        (o for o in db_orders if o.id == input.orderId and o.userId == current_customer.id),
        None
    )

    if order is None:
        print("[DEBUG] Pedido no encontrado en db_orders para este cliente")
        raise HTTPException(status_code=404, detail="Pedido no encontrado para este cliente")

    # Simular la pasarela de pago
    transaction_id = f"fake_txn_{uuid4()}"
    print(f"[DEBUG] Pago aprobado. Transacción: {transaction_id}")

    # (Opcional) guardar el pago en db_payments si tienes el modelo Payment
    # ...

    return {
        "provider": input.provider,
        "transactionId": transaction_id,
        "status": "aprobado",
        "amount": input.amount
    }



@app.post(f"{API_PREFIX}/pagos/confirmacion-automatica", response_model=Response, tags=["PagoService"])
def confirm_payment(input: PaymentConfirmationInput):
    """
    (Diagrama 11) Confirmación Automática de Pago (Callback).
    Endpoint PÚBLICO (lo llama la pasarela, no el usuario).
    """
    print(f"Confirmando pago para orden {input.orderId} con TnxID: {input.gatewayTransactionId}")
    # Lógica de BBDD (Simulada)
    order = next((o for o in db_orders if o.id == input.orderId), None)
    if order:
        order.status = "Pagado"
        payment = Payment(
            orderId=input.orderId,
            status="Confirmado",
            authorizationCode=f"auth_{random.randint(1000, 9999)}"
        )
        db_payments.append(payment)
        return Response(message=f"Orden {input.orderId} confirmada")
    else:
        raise HTTPException(status_code=404, detail="Orden no encontrada")

# --- Servicio: Producto (Diagrama 08) ---

@app.get(f"{API_PREFIX}/productos/filtrar-buscar", response_model=Response, tags=["ProductService"])
def search_products(filter_input: SearchFilterInput = Depends()):
    """
    (Diagrama 08) Filtrar y Buscar Productos.
    Usa Query Params: ?keywords=pollo&category=asado
    """
    print(f"Buscando productos con: {filter_input.model_dump_json(exclude_none=True)}")
    # Lógica de BBDD (Simulada)
    return Response(data=[
        {"id": "fake_prod_1", "nombre": "Pollo Asado"},
        {"id": "fake_prod_2", "nombre": "Papas Fritas"}
    ])

# --- Servicio: Operaciones (Diagramas 14, 15, 17, 18, 19, 20) ---

@app.get(f"{API_PREFIX}/cocina/panel-control", response_model=List[KitchenTicket], tags=["OperacionesService"])
def get_kitchen_panel(status: str):
    """
    (Diagrama 14) Panel Control Cocina.
    Usa Query Params: ?status=Pendiente
    """
    print(f"Buscando tickets de cocina con estado: {status}")
    # Lógica de BBDD (Simulada)
    tickets = [t for t in db_kitchen_tickets if t.status == status]
    return tickets
# --- Servicio: Cocina ---
@app.post(f"{API_PREFIX}/cocina/ticket", tags=["KitchenService"], response_model=KitchenTicket)
def generate_kitchen_ticket(
    input: DigitalInvoiceInput,   # solo usamos orderId
    current_customer: Customer = Depends(get_current_customer)
):
    """
    (Diagrama 15) Generación de Ticket de Cocina.
    Endpoint protegido.
    """

    # 1) Verificar que el pedido exista y pertenezca al cliente actual
    order = get_order_for_customer(input.orderId, current_customer.id)
    if order is None:
        raise HTTPException(status_code=404, detail="Pedido no encontrado para este cliente")

    # 2) Verificar si YA EXISTE ticket de cocina
    existing_ticket = next(
        (t for t in db_kitchen_tickets if t.orderId == input.orderId),
        None
    )

    if existing_ticket:
        print(f"[DEBUG] Ticket de cocina ya existe para pedido {input.orderId}")
        return existing_ticket

    # 3) Crear ticket nuevo
    ticket = KitchenTicket(
        orderId=input.orderId,
        status="en preparación"
    )

    db_kitchen_tickets.append(ticket)

    print(f"[DEBUG] Ticket generado para pedido {input.orderId}: {ticket.id}")

    return ticket

@app.post(f"{API_PREFIX}/cocina/alertas-coccion", response_model=Response, tags=["OperacionesService"])
def set_cooking_alert(input: CookingTimeAlertInput):
    """ (Diagrama 15) Alertas Tiempos de Cocción """
    print(f"Alerta creada para ticket {input.ticketId} a los {input.thresholdMinutes} min.")
    return Response(message="Alerta creada")
# --- Servicio: Tracking (Diagrama 16) ---

@app.post(f"{API_PREFIX}/tracking/actualizar", response_model=Tracking, tags=["TrackingService"])
def update_tracking(
    input: TrackingUpdateInput,
    current_customer: Customer = Depends(get_current_customer)
):
    """
    (Diagrama 16) Actualización de Tracking de Pedido.
    Endpoint protegido.
    """

    # 1) Verificar que el pedido exista y pertenezca al cliente actual
    order = get_order_for_customer(input.orderId, current_customer.id)
    if order is None:
        raise HTTPException(
            status_code=404,
            detail="Pedido no encontrado para este cliente"
        )

    # 2) Buscar tracking existente
    tracking = next(
        (t for t in db_trackings if t.orderId == input.orderId),
        None
    )

    # 3) Crear si no existe
    if tracking is None:
        tracking = Tracking(
            orderId=input.orderId,
            status=input.status
        )
        db_trackings.append(tracking)
        print(f"[DEBUG] Tracking creado para pedido {input.orderId}: {tracking.status}")

    else:
        # 4) Actualizar
        tracking.status = input.status
        tracking.updatedAt = datetime.now()
        print(f"[DEBUG] Tracking actualizado para pedido {input.orderId}: {tracking.status}")

    return tracking

API_PREFIX = "/api/pollosabroso"  # declarada solo una vez en todo el archivo

@app.get(f"{API_PREFIX}/tracking/{{orderId}}", response_model=Tracking, tags=["Tracking"])
def get_tracking(orderId: UUID, db: Session = Depends(get_db)):
    """
    (Diagrama 16) Consultar Tracking de Pedido.
    Lee el tracking desde la base de datos (tabla tracking).
    """

    # Como order_id es String(36), comparamos con str(orderId)
    tracking_orm = (
        db.query(TrackingORM)
        .filter(TrackingORM.order_id == str(orderId))
        .order_by(TrackingORM.updated_at.desc())
        .first()
    )

    if not tracking_orm:
        raise HTTPException(status_code=404, detail="Tracking no encontrado")

    # ORM -> Pydantic
    tracking = Tracking(
        id=tracking_orm.id,              # Pydantic lo convierte a UUID
        orderId=tracking_orm.order_id,   # idem
        status=tracking_orm.status,
        lat=None,                        # no existen en la BD, por eso los dejamos en None
        lng=None,
        updatedAt=tracking_orm.updated_at,
    )

    return tracking



@app.post(f"{API_PREFIX}/reparto/asignacion-automatica", response_model=Response, tags=["OperacionesService"])
def assign_driver(
    input: AutoDriverAssignmentInput,
    db: Session = Depends(get_db)
):
    """
    (Diagrama 17) Asignación Automática de Repartidores (MySQL).
    Asigna un repartidor real al pedido y actualiza el tracking.
    """
    # 1) Buscar tracking del pedido
    tracking_orm = (
        db.query(TrackingORM)
        .filter(TrackingORM.order_id == str(input.orderId))
        .order_by(TrackingORM.updated_at.desc())
        .first()
    )

    if not tracking_orm:
        raise HTTPException(status_code=404, detail="Tracking no encontrado para ese pedido")

    # 2) Buscar repartidores
    drivers = db.query(DeliveryPersonORM).all()
    if not drivers:
        raise HTTPException(status_code=400, detail="No hay repartidores registrados")

    # 3) Elegir uno al azar
    chosen_driver = random.choice(drivers)

    # 4) Actualizar tracking
    tracking_orm.driver_id = chosen_driver.id
    tracking_orm.status = "Asignado"
    tracking_orm.updated_at = datetime.now()

    db.commit()
    db.refresh(tracking_orm)

    # 5) Devolver info
    return Response(
        data={
            "orderId": tracking_orm.order_id,
            "driverId": chosen_driver.id,
            "driverName": chosen_driver.name,
            "status": tracking_orm.status,
        }
    )


@app.post(f"{API_PREFIX}/reparto/planificacion-rutas", response_model=Response, tags=["OperacionesService"])
def plan_routes(input: RoutePlanningInput):
    """ (Diagrama 18) Planificación de Rutas """
    print(f"Planificando rutas para {len(input.orders)} órdenes.")
    return Response(data={"stops": len(input.orders), "optimizedBy": "simulador"})

@app.get(f"{API_PREFIX}/reparto/panel", response_model=Response, tags=["OperacionesService"])
def get_courier_panel(
    driverId: UUID,
    db: Session = Depends(get_db)
):
    """
    (Diagrama 19) Panel de Repartidor.
    Usa Query Param: ?driverId=...
    Muestra todos los pedidos asignados a ese repartidor.
    """

    trackings = db.query(TrackingORM).filter(
        TrackingORM.driver_id == str(driverId)
    ).all()

    pedidos = []
    for tr in trackings:
        pedidos.append(
            {
                "orderId": tr.order_id,
                "status": tr.status,
                "updatedAt": tr.updated_at,
            }
        )

    return Response(data=pedidos)


@app.get(f"{API_PREFIX}/pedidos/seguimiento", response_model=Tracking, tags=["OperacionesService"])
def track_order(orderId: UUID):
    """
    (Diagrama 20) Seguimiento del Pedido.
    Usa Query Params: ?orderId=...
    """
    print(f"Obteniendo seguimiento para orden {orderId}")
    # Lógica de BBDD (Simulada)
    tracking_data = Tracking(
        orderId=orderId,
        lat=Decimal("-33.456") + Decimal(random.uniform(-0.01, 0.01)),
        lng=Decimal("-70.678") + Decimal(random.uniform(-0.01, 0.01)),
        updatedAt=datetime.now()
    )
    db_trackings.append(tracking_data)
    return tracking_data

# --- Servicio: Notificacion (Diagramas 13, 16, 23, 24) ---

@app.post(f"{API_PREFIX}/boletas/envio", response_model=Response, tags=["NotificationService"])
def send_invoice_email(input: SendInvoiceEmailInput):
    """ (Diagrama 13) Envio de Boletas por Correo """
    print(f"Enviando boleta {input.invoiceId} a {input.email}")
    return Response(message="Boleta enviada")

@app.post(f"{API_PREFIX}/notificaciones/cliente", response_model=Response, tags=["NotificationService"])
def send_customer_notification(input: CustomerNotificationInput):
    """ (Diagrama 16) Notificacion al Cliente """
    print(f"Enviando notificación '{input.title}' a {input.userId}")
    return Response(message="Notificación enviada")

@app.post(f"{API_PREFIX}/promociones/recibir", response_model=Response, tags=["NotificationService"])
def send_personalized_promo(input: PersonalizedPromotionInput):
    """ (Diagrama 23) Recibir Promociones Personalizadas """
    print(f"Enviando promo '{input.title}' a segmento {input.segment}")
    return Response(message="Promoción enviada")

@app.post(f"{API_PREFIX}/promociones/recordatorio", response_model=Response, tags=["NotificationService"])
def send_promo_reminder(input: PromotionReminderInput):
    """ (Diagrama 24) Recordatorio de Promociones """
    print(f"Programando recordatorio '{input.title}' para {input.userId} en canal {input.channel}")
    return Response(message="Recordatorio programado")

# --- Servicio: Documento (Diagrama 12) ---

@app.post(f"{API_PREFIX}/facturas/generar", response_model=Invoice, tags=["InvoiceService"])
def generate_invoice(
    input: DigitalInvoiceInput,
    current_customer: Customer = Depends(get_current_customer)
):
    """
    (Diagrama 11/12) Generación de Boleta / Factura Digital.
    Endpoint protegido.
    """
    # 1) Verificar que el pedido exista y pertenezca al cliente actual
    order = get_order_for_customer(input.orderId, current_customer.id)
    if order is None:
        raise HTTPException(
            status_code=404,
            detail="Pedido no encontrado para este cliente"
        )

    # 2) Verificar si ya existe una factura para este pedido
    existing_invoice = next(
        (inv for inv in db_invoices if inv.orderId == order.id),
        None
    )
    if existing_invoice:
        print(f"[DEBUG] Factura ya existe para pedido {order.id}, devolviendo existente")
        return existing_invoice

    # 3) Generar número de boleta/factura
    invoice_number = f"BOL-{datetime.now().year}-{len(db_invoices) + 1:06}"

    # 4) Construir URL "fake" del PDF (simulado)
    pdf_url = f"https://pollos-abrosos-fake-storage.local/facturas/{invoice_number}.pdf"

    # 5) Crear la boleta/factura
    new_invoice = Invoice(
        orderId=order.id,
        number=invoice_number,
        total=input.amount,
        pdfUrl=pdf_url,
        # generatedAt se llena solo por el Field(default_factory=datetime.now)
    )

    # 6) Guardar en la "BD" en memoria
    db_invoices.append(new_invoice)

    print(f"[DEBUG] Factura generada para pedido {order.id}: {invoice_number}")

    # 7) Devolver la boleta/factura generada
    return new_invoice


# --- Servicio: Misc (Diagramas 25, 26) ---

@app.post(f"{API_PREFIX}/formularios/enviar", response_model=Response, tags=["MiscService"])
def submit_form(input: FormSubmissionInput, current_customer: Customer = Depends(get_current_customer)):
    """
    (Diagrama 25) Formularios (Ej. Contacto, Reclamos).
    Endpoint protegido.
    """
    print(f"Recibido formulario '{input.type}' de {current_customer.email}")
    return Response(message="Formulario recibido")

@app.post(f"{API_PREFIX}/integracion/sistema-datos", response_model=Response, tags=["MiscService"])
def sync_data(input: DataSystemIntegrationInput):
    """
    (Diagrama 26) Integracion Sistema de Datos (Admin/Interno).
    Endpoint protegido (simulación omitida).
    """
    print(f"Integrando {input.records} registros de {input.source}")
    return Response(message="Integración completada")