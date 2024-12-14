FROM gcc:latest

WORKDIR /app

COPY file /app/file

COPY sandbox /app

# Ensure the sandbox script is executable
RUN chmod +x ./sandbox

# Set the default entrypoint to execute the sandbox script
ENTRYPOINT ["sh", "-c"]

# RUN ./sandbox ./file/safe/common_code_csv.csv & ./sandbox ./file/safe/test & ./sandbox ./file/dangerous/a.unknown & wait

# Run sandbox commands at runtime
CMD ./sandbox ./file/safe/common_code_csv.csv & ./sandbox ./file/safe/test & ./sandbox ./file/dangerous/a.unknown & wait


# COPY /app/log /file/log