from fastapi import FastAPI
from routers import classical

app = FastAPI(title="CryptoLab API", version="1.0")

app.include_router(classical.router)

@app.get("/")
def root():
    return {"message": "CryptoLab API running!"}
