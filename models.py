# models.py
from sqlalchemy import Column, String, DateTime, DECIMAL, Integer, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from uuid import uuid4

from database import Base

# -------------------------
# CUSTOMER
# -------------------------
class Customer(Base):
    __tablename__ = "customer"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name = Column(String(100))
    email = Column(String(100), unique=True, nullable=False)
    phone = Column(String(30))
    hashed_password = Column(String(255), nullable=False)

    orders = relationship("Order", back_populates="customer")


# -------------------------
# ORDER
# -------------------------
class Order(Base):
    __tablename__ = "orders"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id = Column(String(36), ForeignKey("customer.id"))
    total = Column(DECIMAL(10,2))
    created_at = Column(DateTime, default=datetime.now)

    customer = relationship("Customer", back_populates="orders")
    items = relationship("OrderItem", back_populates="order")
    tracking = relationship("Tracking", back_populates="order", uselist=False)


# -------------------------
# ORDER ITEM
# -------------------------
class OrderItem(Base):
    __tablename__ = "order_item"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    order_id = Column(String(36), ForeignKey("orders.id"))
    product_name = Column(String(100))
    quantity = Column(Integer)
    price = Column(DECIMAL(10,2))

    order = relationship("Order", back_populates="items")


# -------------------------
# TRACKING
# -------------------------
class Tracking(Base):
    __tablename__ = "tracking"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    order_id = Column(String(36), ForeignKey("orders.id"))
    status = Column(String(50))
    updated_at = Column(DateTime, default=datetime.now)

    # NUEVO: coincide con tu columna en MySQL
    driver_id = Column(String(36), ForeignKey("delivery_person.id"), nullable=True)

    # Relaciones
    order = relationship("Order", back_populates="tracking")
    driver = relationship("DeliveryPerson", back_populates="deliveries")



# -------------------------
# DELIVERY PERSON
# -------------------------
class DeliveryPerson(Base):
    __tablename__ = "delivery_person"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name = Column(String(100))
    phone = Column(String(30))

    # NUEVO: relación inversa
    deliveries = relationship("Tracking", back_populates="driver")
