# Usa una imagen base con Python
FROM python:3.10-slim

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos de tu proyecto al contenedor
COPY . /app
COPY templates/ /app/templates/
COPY static/ /app/static/


# Instala las dependencias de tu aplicación
RUN pip install --no-cache-dir -r requirements.txt

# Expone el puerto 8080 para que la aplicación sea accesible
EXPOSE 8080

# Define el comando para ejecutar la aplicación con Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "main:app"]
