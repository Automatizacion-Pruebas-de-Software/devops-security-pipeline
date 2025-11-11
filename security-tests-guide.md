# Pruebas de Seguridad Locales

## 🔍 Pruebas que se pueden ejecutar localmente

### 1. SAST - Análisis Estático de Código

#### Bandit Security Scan

```bash
# Comando local
bandit -r src/ -f json -o bandit-results.json -ll --skip B101,B301

# Explicación detallada:
bandit -r src/           # -r: recursivo en directorio src/
-f json                  # -f: formato de salida JSON
-o bandit-results.json   # -o: archivo de salida
-ll                      # -ll: nivel de severidad (LOW, MEDIUM, HIGH)
--skip B101,B301         # Omite reglas específicas

# Objetivo: Encontrar vulnerabilidades comunes en código Python
# Por qué estas opciones:
# - JSON output: Para integración con otras herramientas
# - Skip B101: Assert statements (usados en tests)
# - Skip B301: pickle module (puede ser necesario)
```

#### Semgrep OWASP Scan

```bash
# Comando local
docker run --rm -v "$(pwd)/src:/src" returntocorp/semgrep semgrep --config=p/owasp-top-ten --config=p/security-audit /src/

# Explicación detallada:
docker run --rm                    # Ejecuta contenedor y lo elimina después
-v "$(pwd)/src:/src"              # Monta directorio local en contenedor
returntocorp/semgrep              # Imagen oficial de Semgrep
semgrep --config=p/owasp-top-ten  # Reglas OWASP Top 10
--config=p/security-audit         # Reglas de auditoría de seguridad
/src/                             # Directorio a escanear

# Objetivo: Detectar patrones de vulnerabilidad OWASP en el código
# Por qué Docker: Asegura ambiente consistente sin instalación local
```

### 2. SCA - Análisis de Dependencias

#### Trivy Vulnerability Scan

```bash
# Instalación local
# Opción 1: Docker
docker run --rm -v $(pwd):/src aquasec/trivy:latest fs --format sarif /src

# Opción 2: Binario local
trivy fs --format sarif .

# Explicación:
fs                         # Filesystem scan (no container image)
--format sarif             # SARIF format para GitHub/otros tools
.                          # Directorio actual

# Objetivo: Encontrar CVEs en dependencias Python
# Por qué SARIF: Estándar para reportar vulnerabilidades
```

#### OWASP Dependency Check

```bash
# Comando local optimizado
mkdir -p reports
mkdir -p .dependency-check-data

docker run --rm \
  -v "$(pwd):/src" \
  -v "$(pwd)/.dependency-check-data:/usr/share/dependency-check/data" \
  -w /src \
  owasp/dependency-check:latest \
  --scan "/src/requirements.txt" \
  --scan "/src/requirements-test.txt" \
  --format "JSON" \
  --out reports \
  --project "DevOps-Security-App" \
  --disableArchive \
  --log reports/dependency-check.log

# Explicación detallada:
-v "$(pwd)/.dependency-check-data:/usr/share/dependency-check/data"  # Cache local de CVEs
--scan "/src/requirements.txt"              # Archivos específicos a escanear
--disableArchive                           # Más rápido, no analiza archivos comprimidos
--format "JSON"                            # Output parseable

# Objetivo: Análisis profundo de vulnerabilidades en dependencias
# Por qué cache local: Evita descargar CVEs repetidamente
```

#### Snyk Security Scan

```bash
# Instalación local
npm install -g snyk        # O via pip: pip install snyk
snyk auth $SNYK_TOKEN      # Autenticación
snyk test --severity-threshold=high

# Comando equivalente local:
snyk test --file=requirements.txt --severity-threshold=high --json

# Objetivo: Scanner comercial especializado en dependencias
# Por qué severity-threshold=high: Enfocarse en vulnerabilidades críticas
```

### 3. 🧪 Custom Security Tests

#### Ejecutar Tests de Seguridad Personalizados

```bash
# Instalar dependencias de testing
pip install -r requirements-test.txt
pip install pytest pytest-cov

# Ejecutar tests específicos
python -m pytest tests/test_jwt_security.py -v --cov=src/auth --cov-report=xml
python -m pytest tests/test_session_management.py -v
python -m pytest tests/test_input_validation.py -v
python -m pytest tests/test_sql_injection.py -v

# Explicación de cada test:
# test_jwt_security.py: Verifica implementación segura de JWT
# test_session_management.py: Tests de gestión de sesiones
# test_input_validation.py: Validación de entradas de usuario
# test_sql_injection.py: Protección contra inyección SQL

# Objetivo: Validar implementaciones de seguridad específicas
# Por qué cobertura: Medir qué código está siendo probado
```

### 4. DAST - Análisis Dinámico (Local con limitaciones)

#### OWASP ZAP Scan Local

```bash
# Esta es la imagen oficial actual de ZAP
docker pull ghcr.io/zaproxy/zaproxy:stable
docker run -u zap -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:5000 -a -I -m 5

# O con la API:
docker run -u zap -p 8080:8080 owasp/zap2docker-stable zap.sh \
  -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true

# Explicación:
-a          # Ajax spider (para aplicaciones modernas)
-I          # No fallar en errores de dependencias
-m 5        # Solo fallar con vulnerabilidades HIGH/CRITICAL

# Objetivo: Encontrar vulnerabilidades en aplicación ejecutándose
# Limitación local: Necesita la aplicación corriendo
```

## 🛠️ Script Local Unificado

### security-scan-local.sh

```bash
#!/bin/bash
set -e

echo "🛡️  Iniciando Scaneo de Seguridad Local"

# 1. SAST - Bandit
echo "🔍 Ejecutando Bandit..."
bandit -r src/ -f json -o bandit-results.json -ll --skip B101,B301 || true

# 2. SAST - Semgrep
echo "🔍 Ejecutando Semgrep..."
docker run --rm -v "$(pwd)/src:/src" returntocorp/semgrep semgrep --config=p/owasp-top-ten --config=p/security-audit /src/ || true

# 3. SCA - Trivy
echo "📦 Ejecutando Trivy..."
trivy fs --format sarif . > trivy-results.sarif || true

# 4. SCA - OWASP Dependency Check
echo "📋 Ejecutando OWASP Dependency Check..."
mkdir -p reports
docker run --rm \
  -v "$(pwd):/src" \
  -v "$(pwd)/.dependency-check-data:/usr/share/dependency-check/data" \
  -w /src \
  owasp/dependency-check:latest \
  --scan "/src/requirements.txt" \
  --scan "/src/requirements-test.txt" \
  --format "JSON" \
  --out reports \
  --project "Local-Scan" \
  --disableArchive || true

# 5. Tests de Seguridad
echo "🧪 Ejecutando Security Tests..."
python -m pytest tests/ --cov=src --cov-report=xml --cov-report=html -v || true

echo "✅ Scaneo Local Completado"
echo "📊 Resultados en: bandit-results.json, trivy-results.sarif, reports/, coverage.xml"
```