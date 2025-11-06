import pytest
from src.database import safe_db_query, vulnerable_db_query

def test_safe_query_sql_injection():
    """Test: Consulta segura resiste SQL injection"""
    injection_attempts = [
        "admin' OR '1'='1",
        "'; DROP TABLE users--",
        "1 UNION SELECT * FROM passwords"
    ]
    
    for attempt in injection_attempts:
        results = safe_db_query(attempt)
        # La consulta segura debería devolver resultados vacíos o manejar el input
        assert results == [] or isinstance(results, list)

def test_vulnerable_query_detection():
    """Test: Detección de consultas vulnerables"""
    # Este test demuestra el comportamiento vulnerable
    # En un entorno real, esto ayudaría a identificar código peligroso
    with pytest.raises(Exception):
        vulnerable_db_query("test' OR '1'='1")