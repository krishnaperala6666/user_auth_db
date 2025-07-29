from fastapi import FastAPI
from app.routers import user_routes

app = FastAPI(title="User Registration & Auth System")
app.include_router(user_routes.router)