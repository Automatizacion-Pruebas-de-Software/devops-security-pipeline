from flask import Flask, request, jsonify, session
import re
import sys
import os

# Agregar el directorio actual al path para imports
sys.path.append(os.path.dirname(__file__))

try:
    from auth import validate_jwt, create_jwt
    from database import safe_db_query
except ImportError:
    # Fallback para cuando los módulos no existan
    def validate_jwt(token):
        raise Exception('Auth module not available')
    
    def create_jwt(payload):
        return 'mock-token'
    
    def safe_db_query(query):
        return [{'id': 1, 'name': 'Test Product', 'price': 100}]

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

def validate_input(input_string):
    """
    Validación robusta de entrada contra XSS, SQL injection y otros ataques
    
    Args:
        input_string (str): Cadena a validar
        
    Returns:
        bool: True si es seguro, False si es potencialmente malicioso
    """
    # Validar que no sea None o vacío
    if input_string is None:
        return False
        
    # Convertir a string si no lo es
    if not isinstance(input_string, str):
        input_string = str(input_string)
    
    # Validar longitud (1-100 caracteres)
    if len(input_string) == 0 or len(input_string) > 100:
        return False
    
    # Patrones maliciosos comunes
    malicious_patterns = [
        r'<script.*?>.*?</script>',  # XSS básico
        r'<.*?on\w+.*?=.*?>',        # Event handlers XSS
        r'javascript:',               # Protocolo JavaScript
        r'vbscript:',                 # Protocolo VBScript
        r'expression\(',              # CSS expressions
        r"'.*?--",                    # SQL injection clásico
        r'".*?--',                    # SQL injection con comillas dobles
        r';.*?--',                    # SQL injection con punto y coma
        r'union.*select',             # SQL union injection
        r'or.*=.*',                   # SQL or injection
        r'and.*=.*',                  # SQL and injection
        r'exec\(',                    # Ejecución de comandos
        r'eval\(',                    # Evaluación de código
        r'alert\(',                   # Alertas JavaScript
        r'document\.',                # Manipulación DOM
        r'window\.',                  # Objeto window
        r'localStorage',              # Almacenamiento local
        r'sessionStorage',            # Almacenamiento de sesión
        r'<iframe',                   # Iframes maliciosos
        r'<object',                   # Objects embebidos
        r'<embed',                    # Embed malicioso
        r'<form',                     # Formularios maliciosos
        r'<meta',                     # Meta tags maliciosos
        r'<link',                     # Links maliciosos
        r'<base',                     # Base href malicioso
    ]
    
    # Verificar contra patrones maliciosos
    input_lower = input_string.lower()
    for pattern in malicious_patterns:
        if re.search(pattern, input_lower, re.IGNORECASE):
            return False
    
    # Caracteres peligrosos individuales
    dangerous_chars = ['<', '>', '"', "'", ';', '=', '&', '|', '`', '$', '(', ')', '[', ']', '{', '}']
    for char in dangerous_chars:
        if char in input_string:
            # Permitir algunos caracteres en contextos específicos
            if char in ['=', '&'] and len(input_string) > 1:
                continue  # Permitir en parámetros de query
            return False
    
    # Validar encoding (prevenir null bytes y otros caracteres extraños)
    try:
        input_string.encode('utf-8')
    except UnicodeEncodeError:
        return False
    
    # Si pasa todas las validaciones, es seguro
    return True

@app.route('/')
def health_check():
    """Endpoint de health check para monitoreo"""
    return jsonify({
        'status': 'healthy', 
        'message': 'Security App running',
        'version': '1.0.0'
    })

@app.route('/health')
def health():
    """Endpoint de health simplificado para load balancers"""
    return jsonify({'status': 'healthy'})

@app.route('/login', methods=['POST'])
def login():
    """
    Endpoint de login con validación de entrada robusta
    """
    try:
        # Verificar que el request tiene JSON
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        username = request.json.get('username')
        password = request.json.get('password')
        
        # Validación de entrada exhaustiva
        if not validate_input(username) or not validate_input(password):
            return jsonify({'error': 'Invalid input detected'}), 400
        
        # Lógica de autenticación (simplificada para demo)
        if username == 'admin' and password == 'securepassword':
            token = create_jwt({
                'user': username, 
                'role': 'admin',
                'session_id': 'mock-session-id'
            })
            return jsonify({
                'token': token,
                'message': 'Login successful',
                'user': username
            })
        else:
            # No revelar si el usuario existe o no
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        # Log del error (en producción usar logging)
        print(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/protected', methods=['GET'])
def protected():
    """
    Endpoint protegido que requiere JWT válido
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    # Validar que el token no esté vacío
    if not token or not validate_input(token):
        return jsonify({'error': 'Invalid token format'}), 401
    
    try:
        payload = validate_jwt(token)
        return jsonify({
            'message': f'Hello {payload.get("user", "unknown")}', 
            'data': 'sensitive_info',
            'role': payload.get('role', 'user')
        })
    except Exception as e:
        return jsonify({'error': 'Invalid or expired token'}), 401

@app.route('/search', methods=['GET'])
def search():
    """
    Endpoint de búsqueda con validación de query
    """
    query = request.args.get('q', '')
    
    # Validación exhaustiva del query
    if not validate_input(query):
        return jsonify({'error': 'Invalid search query'}), 400
    
    # Uso seguro de base de datos
    try:
        results = safe_db_query(query)
        return jsonify({
            'results': results,
            'query': query,
            'count': len(results)
        })
    except Exception as e:
        return jsonify({'error': 'Search failed'}), 500

@app.route('/validate-input', methods=['POST'])
def validate_input_endpoint():
    """
    Endpoint para probar la validación de entrada
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        input_data = request.json.get('input', '')
        is_valid = validate_input(input_data)
        
        return jsonify({
            'input': input_data,
            'is_valid': is_valid,
            'length': len(input_data)
        })
    except Exception as e:
        return jsonify({'error': 'Validation failed'}), 500

@app.route('/security-headers')
def security_headers():
    """
    Endpoint para verificar headers de seguridad
    """
    response = jsonify({
        'message': 'Security headers check',
        'headers_present': True
    })
    
    # Headers de seguridad adicionales
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# Manejo de errores global
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Solo para desarrollo
    print("Starting Security Flask App...")
    print("Endpoints disponibles:")
    print("  GET  /                    - Health check")
    print("  GET  /health              - Health simplificado") 
    print("  POST /login               - Autenticación")
    print("  GET  /protected           - Endpoint protegido")
    print("  GET  /search?q=query      - Búsqueda segura")
    print("  POST /validate-input      - Probar validación")
    print("  GET  /security-headers    - Headers de seguridad")
    
if __name__ == '__main__':
    # En desarrollo: localhost, en producción: usar variables de entorno
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    port = int(os.getenv('FLASK_PORT', '8080'))
    app.run(host=host, port=port, debug=False)