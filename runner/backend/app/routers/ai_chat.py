import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from openai import OpenAI

router = APIRouter(prefix="/api/ai", tags=["AI Assistant"])


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)


@router.post("/chat")
def chat(req: ChatRequest):
    if os.getenv("AI_ASSISTANT_ENABLED", "false").lower() != "true":
        raise HTTPException(status_code=403, detail="AI assistant disabled")

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not configured")

    try:
        client = OpenAI(api_key=api_key)

        response = client.responses.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
            input=[
                {
                    "role": "system",
                    "content": (
                        "Você é o Assistente IA do Sistema Magi. "
                        "Responda de forma objetiva, profissional e em português. "
                        "Você atende apenas consultas gerais sobre segurança, alertas, MITRE, NIST, "
                        "CVEs, playbooks, operação de TI e uso geral do sistema. "
                        "Você não executa ações, não altera dados, não consulta banco, não acessa sistemas internos "
                        "e não promete automações reais. Quando não souber algo, diga que não tem contexto suficiente."
                    ),
                },
                {"role": "user", "content": req.message},
            ],
        )

        return {"answer": response.output_text}

    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"AI request failed: {exc}")
