docker build -t github-events-limiter .
docker run -it --rm --env-file .env -v "%cd%\GitHub_Events_Limiter:/app/GitHub_Events_Limiter" -p 5000:5000 github-events-limiter