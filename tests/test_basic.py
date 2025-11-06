def test_basic_imports():
    """Test que verifica que todas las dependencias se importan correctamente"""
    try:
        import flask
        import jwt
        import bcrypt
        import pytest
        import bandit
        import requests
        assert True
    except ImportError as e:
        assert False, f"Error de importación: {e}"

def test_basic_assertion():
    """Test básico para verificar que pytest funciona"""
    assert 1 + 1 == 2
