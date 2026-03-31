FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency resolution
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy project files and install dependencies
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY app.py .

EXPOSE 3000

CMD ["uv", "run", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "3000"]
