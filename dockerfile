# Utiliza una imagen base oficial de Python
FROM python:3.10-slim

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia el archivo de requerimientos y luego instálalos
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copia el resto del código del proyecto en el contenedor
COPY . .

# Expone el puerto en el que se ejecutará la aplicación (por defecto Flask usa el 5000)
EXPOSE 5000


# Establece la variable de entorno para indicar a Flask cuál es la aplicación
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Comando para ejecutar la aplicación
CMD ["flask", "run"]
