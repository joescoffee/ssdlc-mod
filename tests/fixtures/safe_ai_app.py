# Clean counterpart of vulnerable_ai_app.py: must produce no findings.
import torch
from transformers import AutoModel

model = AutoModel.from_pretrained("acme/model", revision="3f2a1c9e0b7d")
weights = torch.load(
    "ckpt.pt",
    weights_only=True,
)
agent = create_agent(llm, tools, max_iterations=8)
client = ClaudeSDKClient(options=Options(permission_mode="default", allowed_tools=["Read", "Grep"]))
config = {"use_docker": True}
html = sanitize(markdown(reply.content))
