docker build -t debug-image .
docker run -it --rm --env-file .env -v "%cd%\config.json:/app/config.json" -p 5000:5000 debug-image