# /bin/bash
STREAMLIT_PORT=8888 docker compose -f compose.yaml down
STREAMLIT_PORT=8888 docker compose -f compose.yaml up --build -d
