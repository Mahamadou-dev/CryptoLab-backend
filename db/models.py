from pydantic import BaseModel
from datetime import datetime

class SimulationResult(BaseModel):
    algorithm: str
    action: str   # encrypt / decrypt / hash
    input_text: str
    output_text: str
    timestamp: datetime
