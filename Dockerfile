# Create builder image to reduce final size.
FROM python:3.12-alpine as builder

# Set project working directory.
WORKDIR /usr/src/project

# Copy requirements.txt first to allow for dependency caching.
COPY requirements.txt .

# Install build dependencies and Python packages
RUN apk add --no-cache --virtual .build-deps gcc musl-dev cairo-dev \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --user -r requirements.txt \
    && apk del .build-deps

# Create production stage.
FROM python:3.12-alpine

# Set project working directory.
WORKDIR /usr/src/project

# Copy installed packages from builder stage
COPY --from=builder /root/.local /root/.local

# Copy the rest of the project files to working directory.
COPY . .

# Make sure scripts in .local are usable in the production image.
ENV PATH=/root/.local/bin:$PATH
