# Use GCC as the base image
FROM gcc:latest

# Install dependencies for libmagic and other tools
RUN apt-get update && apt-get install -y \
    libmagic-dev \       
    # Install libmagic development libraries
    evince \              
    # PDF viewer (if needed)
    wine \                
    # Windows EXE runner (if needed)
    default-jre \         
    # Java runtime (if needed)
    python3 \             
    # Python (if needed)
    nodejs \              
    # Node.js (if needed)
    libreoffice && \      
    # Excel, Word (if needed)
    apt-get clean

# Set the working directory inside the container
WORKDIR /app

# Copy the source code 'sandbox.c' and script 'entrypoint.sh' into the /app directory
# COPY test /app/test
# COPY sandbox_basic.c /app/sandbox_basic.c
COPY sandbox /app/sandbox


# Compile the C program using libmagic
# RUN gcc -o sandbox sandbox_basic.c -lmagic

# Ensure that the binary files are executable
RUN chmod +x sandbox

# Set the working directory to /app (optional, to simplify paths)
WORKDIR /app

# Set the entrypoint to the custom script
ENTRYPOINT ["./sandbox"]
