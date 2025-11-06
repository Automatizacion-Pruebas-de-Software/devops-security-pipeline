import sqlite3
import re

def safe_db_query(user_input):
    """Consulta segura a base de datos"""
    # Simulación de base de datos
    sample_data = [
        {'id': 1, 'name': 'Product 1', 'price': 100},
        {'id': 2, 'name': 'Product 2', 'price': 200}
    ]
    
    # Validación contra SQL injection
    if not re.match(r'^[a-zA-Z0-9\s]+$', user_input):
        return []
    
    # Búsqueda segura
    results = [item for item in sample_data 
              if user_input.lower() in item['name'].lower()]
    
    return results

def vulnerable_db_query(user_input):
    """Ejemplo de consulta vulnerable (para testing)"""
    # ¡NO USAR EN PRODUCCIÓN!
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    # VULNERABLE: Concatenación directa
    query = f"SELECT * FROM products WHERE name = '{user_input}'"
    cursor.execute(query)  # ¡PELIGRO!
    
    return cursor.fetchall()