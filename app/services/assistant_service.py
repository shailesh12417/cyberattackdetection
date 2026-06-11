from typing import TypedDict

from langgraph.graph import END, StateGraph
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage

from app.core.config import get_settings
from app.schemas.prediction import ChatMessage, DatasetSummary, RecordPrediction

try:
    from langchain_groq import ChatGroq
except Exception:  # pragma: no cover
    ChatGroq = None


class AnalysisState(TypedDict):
    summary: DatasetSummary
    predictions: list[RecordPrediction]
    assistant_summary: str
    remediation: list[str]


class ChatState(TypedDict):
    message: str
    history: list[ChatMessage]
    latest_summary: DatasetSummary | None
    reply: str


class AssistantService:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.graph = self._build_graph()
        self.chat_graph = self._build_chat_graph()

    def _build_graph(self):
        workflow = StateGraph(AnalysisState)
        workflow.add_node("summarize", self._summarize)
        workflow.add_node("recommend", self._recommend)
        workflow.set_entry_point("summarize")
        workflow.add_edge("summarize", "recommend")
        workflow.add_edge("recommend", END)
        return workflow.compile()

    def _build_chat_graph(self):
        workflow = StateGraph(ChatState)
        workflow.add_node("respond", self._respond)
        workflow.set_entry_point("respond")
        workflow.add_edge("respond", END)
        return workflow.compile()

    def _get_llm(self):
        if not self.settings.groq_api_key or ChatGroq is None:
            return None
        return ChatGroq(
            model=self.settings.groq_model,
            api_key=self.settings.groq_api_key,
            temperature=0.2,
        )

    @property
    def llm_enabled(self) -> bool:
        return bool(self.settings.groq_api_key and ChatGroq is not None)

    def _summarize(self, state: AnalysisState) -> AnalysisState:
        llm = self._get_llm()
        if llm is None:
            state["assistant_summary"] = self._fallback_summary(state["summary"])
            return state

        try:
            messages = [
                SystemMessage(content="You are a SOC analyst assistant. Summarize the network attack prediction results in 4 concise lines."),
                HumanMessage(content=f"Summary: {state['summary'].model_dump_json()} Predictions: {[item.model_dump() for item in state['predictions'][:5]]}")
            ]
            response = llm.invoke(messages)
            state["assistant_summary"] = response.content if hasattr(response, "content") else str(response)
        except Exception:
            state["assistant_summary"] = self._fallback_summary(state["summary"])
        return state

    def _fallback_summary(self, summary: DatasetSummary) -> str:
        distribution = ", ".join(f"{name}: {count}" for name, count in summary.attack_distribution.items())
        return (
            f"Analyzed {summary.total_records} records. "
            f"Highest severity observed is {summary.highest_severity}. "
            f"Attack mix: {distribution or 'no attacks detected'}."
        )

    def _recommend(self, state: AnalysisState) -> AnalysisState:
        highest = state["summary"].highest_severity
        if highest in {"critical", "high"}:
            state["remediation"] = [
                "Isolate affected hosts or subnets showing repeated malicious patterns.",
                "Block suspicious IPs, ports, or services at firewall and IDS layers.",
                "Collect packet captures and authentication logs for forensic validation.",
                "Rotate credentials and review lateral movement indicators for impacted users.",
            ]
        elif highest == "medium":
            state["remediation"] = [
                "Increase IDS/IPS sensitivity for the flagged services and protocols.",
                "Review unusual connection bursts and compare them with baseline traffic.",
                "Validate whether repeated probes originate from trusted assets or scans.",
            ]
        else:
            state["remediation"] = [
                "Continue monitoring traffic and retrain the model on the latest clean data.",
                "Review false positives and update feature engineering for better precision.",
            ]
        return state

    def _format_history(self, history: list[ChatMessage]) -> str:
        if not history:
            return "No previous conversation."
        return "\n".join(
            f"{message.role.title()}: {message.content}" for message in history[-8:]
        )

    def _contains_any(self, message: str, keywords: list[str]) -> bool:
        lowered = message.lower()
        return any(keyword in lowered for keyword in keywords)

    def _is_greeting(self, message: str) -> bool:
        return message.lower().strip() in {
            "hi",
            "hello",
            "hey",
            "hii",
            "yo",
            "good morning",
            "good afternoon",
            "good evening",
        }

    def _format_summary_context(self, latest_summary: DatasetSummary) -> str:
        attack_types = {k: v for k, v in latest_summary.attack_distribution.items() if k.lower() not in {"normal", "benign"}}
        attack_mix = ", ".join(f"{label}: {count}" for label, count in attack_types.items()) or "no malicious patterns"
        
        return (
            f"Current traffic session: {latest_summary.total_records} records total, "
            f"{latest_summary.malicious_records} flagged as malicious, highest severity {latest_summary.highest_severity}. "
            f"Breakdown of detected attacks: {attack_mix}."
        )

    def _fallback_knowledge_reply(self, message: str) -> str | None:
        lowered = message.lower().strip()
        glossary = {
            "dos": (
                "A DoS attack floods a server or network resource with excessive requests so legitimate users cannot access it. "
                "Typical signs include traffic spikes, many repeated requests, slow response times, and service unavailability."
            ),
            "ddos": (
                "A DDoS attack is a distributed denial-of-service attack where many compromised systems send traffic together. "
                "It is usually harder to block than a single-source DoS because requests come from multiple hosts."
            ),
            "probe": (
                "A probe attack is reconnaissance activity where an attacker scans hosts, ports, or services to discover weaknesses. "
                "It often appears as repeated connection attempts across many ports or systems."
            ),
            "r2l": (
                "R2L means remote-to-local attack. The attacker tries to gain local access from a remote machine, often using stolen credentials, password guessing, or vulnerable services."
            ),
            "u2r": (
                "U2R means user-to-root attack. An attacker who already has limited access tries to escalate privileges to administrator or root level."
            ),
        }

        if lowered in glossary:
            return glossary[lowered]
        if "what is dos" in lowered or "dos attack" in lowered:
            return glossary["dos"]
        if "what is ddos" in lowered or "ddos attack" in lowered:
            return glossary["ddos"]
        if "what is probe" in lowered:
            return glossary["probe"]
        if "what is r2l" in lowered:
            return glossary["r2l"]
        if "what is u2r" in lowered:
            return glossary["u2r"]
        return None

    def _fallback_chat(self, state: ChatState) -> str:
        message = state["message"].strip()
        latest_summary = state["latest_summary"]
        knowledge_reply = self._fallback_knowledge_reply(message)
        summary_context = (
            self._format_summary_context(latest_summary) + " " if latest_summary is not None else ""
        )

        if self._is_greeting(message):
            if latest_summary is not None:
                return (
                    f"{summary_context}"
                    "Ask about the current alert, attack type, mitigation, or model behavior."
                )
            return "Hi. Ask about attack types, suspicious traffic, model predictions, or mitigation steps."

        if knowledge_reply is not None:
            return f"{knowledge_reply} {summary_context}".strip()

        if self._contains_any(message, ["model", "accuracy", "confidence", "prediction"]):
            return (
                f"{summary_context}"
                "The model predicts attack categories from network-flow features such as bytes, service, protocol, and connection rates. "
                "Confidence indicates how strongly the classifier prefers one class over the others, while accuracy reflects performance on test data."
            )

        if self._contains_any(message, ["mitigation", "prevent", "protect", "response", "what should i do"]):
            return (
                f"{summary_context}"
                "Recommended next steps: isolate suspicious hosts if needed, block risky IPs or services, review authentication and packet logs, "
                "and confirm whether the traffic matches known attack behavior before closing the alert."
            )

        if latest_summary is None:
            return (
                "I can help with network security questions, model behavior, attack types, and incident response steps. "
                "Run a traffic analysis as well if you want advice tied to live predictions."
            )

        if self._contains_any(message, ["severity", "high severity", "critical", "risk"]):
            return (
                f"{summary_context}"
                "A high or critical severity alert means the model sees traffic patterns strongly associated with serious attacks. "
                "You should validate the affected host, inspect firewall or IDS logs, and check whether the traffic volume or service usage is abnormal."
            )

        return (
            f"{summary_context}"
            "Based on your question, start by checking the affected systems, reviewing logs for repeated suspicious behavior, "
            "and comparing the flagged traffic with your normal network baseline."
        )

    def _respond(self, state: ChatState) -> ChatState:
        llm = self._get_llm()
        if llm is None:
            state["reply"] = self._fallback_chat(state)
            return state

        latest_summary = (
            state["latest_summary"].model_dump_json() if state["latest_summary"] is not None else "null"
        )
        system_content = (
            "You are a cybersecurity SOC assistant inside a production network defense dashboard. "
            "Answer in a concise, practical way. Use short paragraphs or compact bullet points when useful. "
            "Do not mention that this is a demo, dashboard intro, or welcome message. "
            "For simple greetings like hi or hello, reply in one short line and immediately offer security-focused help. "
            "If the user asks a direct concept question like 'what is dos attack', answer the concept first, then connect it to the detection summary if relevant. "
            "If the question relates to model predictions, use the supplied detection summary. "
            "If the user asks general cyber topics, answer clearly with defensive guidance. Avoid repeating the same summary in every response unless it helps. "
            f"Detection summary: {latest_summary}"
        )
        
        messages = [SystemMessage(content=system_content)]
        for msg in state['history']:
            if msg.role == 'user':
                messages.append(HumanMessage(content=msg.content))
            else:
                messages.append(AIMessage(content=msg.content))
        
        try:
            response = llm.invoke(messages)
            state["reply"] = response.content if hasattr(response, "content") else str(response)
        except Exception:
            state["reply"] = self._fallback_chat(state)
        return state

    def analyze(self, summary: DatasetSummary, predictions: list[RecordPrediction]) -> dict:
        state: AnalysisState = {
            "summary": summary,
            "predictions": predictions,
            "assistant_summary": "",
            "remediation": [],
        }
        result = self.graph.invoke(state)
        return {
            "assistant_summary": result["assistant_summary"],
            "remediation": result["remediation"],
        }

    def chat(
        self,
        message: str,
        history: list[ChatMessage],
        latest_summary: DatasetSummary | None,
    ) -> dict:
        state: ChatState = {
            "message": message,
            "history": history,
            "latest_summary": latest_summary,
            "reply": "",
        }
        result = self.chat_graph.invoke(state)
        return {"reply": result["reply"]}


assistant_service = AssistantService()
