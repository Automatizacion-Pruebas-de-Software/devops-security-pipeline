import jwt
import time
from datetime import datetime, timezone, timedelta

JWT_SECRET = 'CLAVE_FUERTE_SEGURA_123456'
JWT_ALGORITHM = 'HS256'

def create_jwt(payload):
    """Crear JWT seguro con expiración (timezone-aware)"""
    # Usar datetime con timezone en lugar de utcnow()
    payload['exp'] = datetime.now(timezone.utc) + timedelta(minutes=30)
    payload['iat'] = datetime.now(timezone.utc)
    
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def validate_jwt(token):
    """Validar JWT con todas las protecciones"""
    try:
        payload = jwt.decode(
            token, 
            JWT_SECRET, 
            algorithms=[JWT_ALGORITHM],
            options={'verify_exp': True}
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise Exception('Token expired')
    except jwt.InvalidTokenError:
        raise Exception('Invalid token')

def check_jwt_vulnerabilities(token):
    """Detectar vulnerabilidades comunes en JWT"""
    try:
        # Verificar algoritmo none (PyJWT ya lo bloquea por defecto)
        if 'none' in token.lower():
            return False, "None algorithm detected"
        
        # Verificar clave débil
        weak_secrets = ['secret', 'password', '123456', 'clave']
        for weak in weak_secrets:
            try:
                jwt.decode(token, weak, algorithms=['HS256'])
                return False, f"Weak secret detected: {weak}"
            except jwt.InvalidTokenError:
                continue
                
        return True, "JWT appears secure"
    except Exception as e:
        return False, f"JWT validation error: {str(e)}"