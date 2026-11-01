# Deliberately vulnerable LLM/agent fixture for ssdlc tests. Never import or run.
import joblib
import torch
from langchain_community.vectorstores import FAISS
from langchain_core.load import loads                                       # ai.langchain-loads
from langchain_experimental.tools import PythonREPLTool
from transformers import AutoModel

model = AutoModel.from_pretrained("acme/model", trust_remote_code=True)     # ai.trust-remote-code (+ unpinned-model-ref)
store = FAISS.load_local("idx", emb, allow_dangerous_deserialization=True)   # ai.dangerous-deserialization-flag
weights = torch.load("ckpt.pt")                                             # ai.unsafe-model-load
clf = joblib.load("clf.joblib")                                             # ai.unsafe-model-load
tools = [PythonREPLTool()]                                                  # ai.open-ended-agent-tool
agent = create_agent(llm, tools, max_iterations=None)                        # ai.unbounded-agent
client = ClaudeSDKClient(options=Options(permission_mode="bypassPermissions"))  # ai.agent-approval-bypass
config = {"use_docker": False}                                              # ai.agent-unsandboxed-exec
