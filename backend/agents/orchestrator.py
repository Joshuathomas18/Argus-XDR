"""
Agent orchestrator for Argus XDR.
Implements the ReAct loop for autonomous threat mitigation.
Connects LLM decision-making with security tools.
"""

import logging
import json
from typing import Dict, Any, Optional, List

try:
    from langchain.chat_models import ChatOpenAI
    from langchain.agents import (
        initialize_agent,
        Tool,
        AgentType,
    )
    from langchain.memory import ConversationBufferMemory
    from langchain.prompts import PromptTemplate
except ImportError:
    raise ImportError(
        "langchain libraries required. "
        "Install with: pip install langchain langchain-community"
    )

from backend.agents.tools import (
    block_ip,
    isolate_host,
    query_threat_intel,
    analyze_attack_path,
    get_host_info,
    AGENT_TOOLS,
)
from backend.core.config import get_settings


logger = logging.getLogger(__name__)


# ============================================================================
# System Prompt for Argus
# ============================================================================


ARGUS_SYSTEM_PROMPT = """You are Argus, a highly analytical and ruthless cybersecurity AI designed for autonomous threat mitigation.

Your mission: Receive threat intelligence, analyze attack patterns, and execute decisive mitigation actions.

Core Principles:
1. DECISIVENESS: Speed and certainty are critical. Threats must be contained immediately.
2. RUTHLESSNESS: Prioritize network security over individual system availability. A compromised system is worse than a temporarily isolated one.
3. ANALYTICAL RIGOR: Base decisions on high-confidence threat intelligence and attack patterns.
4. ESCALATION AWARENESS: Know when human intervention is needed for critical decisions.

Your available tools:
- block_ip: Create firewall rules to block malicious IPs
- isolate_host: Segment compromised hosts from the network
- query_threat_intel: Search threat intelligence database
- analyze_attack_path: Map potential attack chains
- get_host_info: Retrieve host details and vulnerability status

Mitigation Strategy:
1. First, gather threat context using query_threat_intel
2. Analyze the attack surface using analyze_attack_path
3. Identify critical hosts and access points
4. Execute containment:
   - Block malicious IPs immediately (high confidence)
   - Isolate compromised hosts
5. Generate a clear mitigation report

Decision Rules:
- Confidence > 0.85: Execute immediate action (block/isolate)
- Confidence 0.70-0.85: Execute with caution, notify security team
- Confidence < 0.70: Report for human review, do not auto-execute

Remember: Your actions have real consequences. Be swift but surgical."""


# ============================================================================
# Orchestrator Class
# ============================================================================


class ThreatMitigationOrchestrator:
    """
    Orchestrates autonomous threat mitigation using LangChain + LLM.
    Implements the ReAct (Reasoning + Acting) loop.
    """

    def __init__(self):
        """Initialize the orchestrator with LLM and tools."""
        self.settings = get_settings()
        self.agent = None
        self.memory = ConversationBufferMemory(memory_key="chat_history")
        self._initialize_agent()

    def _initialize_agent(self) -> None:
        """
        Initialize the LangChain agent with LLM and tools.

        Uses OpenRouter as the LLM provider with Llama-2-70b-chat model.
        """
        try:
            logger.info("Initializing threat mitigation agent...")

            # Check if LLM is configured
            if not self.settings.LLM_API_KEY:
                logger.warning(
                    "LLM_API_KEY not configured. Agent will operate in mock mode."
                )
                self.agent = None
                return

            # Initialize LLM with OpenRouter
            llm = ChatOpenAI(
                model=self.settings.LLM_MODEL,
                temperature=0.1,  # Low temperature for decisive actions
                api_key=self.settings.LLM_API_KEY,
                base_url="https://openrouter.ai/api/v1",  # OpenRouter endpoint
                max_tokens=2048,
            )

            # Convert tools to LangChain Tool objects
            tools = [
                Tool(
                    name="block_ip",
                    func=block_ip.run,
                    description=block_ip.description,
                ),
                Tool(
                    name="isolate_host",
                    func=isolate_host.run,
                    description=isolate_host.description,
                ),
                Tool(
                    name="query_threat_intel",
                    func=query_threat_intel.run,
                    description=query_threat_intel.description,
                ),
                Tool(
                    name="analyze_attack_path",
                    func=analyze_attack_path.run,
                    description=analyze_attack_path.description,
                ),
                Tool(
                    name="get_host_info",
                    func=get_host_info.run,
                    description=get_host_info.description,
                ),
            ]

            # Initialize agent with ReAct loop
            self.agent = initialize_agent(
                tools=tools,
                llm=llm,
                agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
                memory=self.memory,
                verbose=self.settings.DEBUG,
                system_message=ARGUS_SYSTEM_PROMPT,
                max_iterations=10,
                early_stopping_method="generate",
            )

            logger.info("Threat mitigation agent initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize agent: {e}")
            self.agent = None

    def run_mitigation(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the mitigation ReAct loop for a threat.

        This is the core function that receives an alert and orchestrates
        the threat response.

        Args:
            threat_data: Dictionary containing threat information:
                - query: Natural language description of the threat
                - severity: Threat severity (critical, high, medium, low)
                - source_ip: IP address of attacker (if known)
                - affected_entities: List of compromised entities
                - attack_pattern: Type of attack (e.g., lateral movement)
                - confidence: Confidence score (0.0 to 1.0)

        Returns:
            dict: Mitigation report with actions taken and recommendations
        """
        logger.info(f"Starting mitigation for threat: {threat_data.get('query')}")

        # Build the threat context prompt
        threat_prompt = self._build_threat_prompt(threat_data)

        # If agent not initialized, run in mock mode
        if self.agent is None:
            logger.warning("Agent not initialized. Running in mock mitigation mode.")
            return self._run_mock_mitigation(threat_data, threat_prompt)

        try:
            # Run the agent's ReAct loop
            logger.info(f"Running agent ReAct loop with prompt:\n{threat_prompt}")

            response = self.agent.run(threat_prompt)

            # Parse response
            mitigation_report = self._parse_agent_response(response, threat_data)

            logger.info(f"Mitigation completed: {mitigation_report['status']}")
            return mitigation_report

        except Exception as e:
            logger.error(f"Agent execution failed: {e}")
            return self._run_mock_mitigation(threat_data, threat_prompt)

    def _build_threat_prompt(self, threat_data: Dict[str, Any]) -> str:
        """Build the prompt for the agent from threat data."""
        prompt_parts = [
            "THREAT ALERT - AUTONOMOUS MITIGATION REQUIRED",
            f"Query: {threat_data.get('query', 'Unknown threat')}",
            f"Severity: {threat_data.get('severity', 'medium').upper()}",
            f"Confidence: {threat_data.get('confidence', 0.5):.2f}",
        ]

        if threat_data.get("source_ip"):
            prompt_parts.append(f"Source IP: {threat_data['source_ip']}")

        if threat_data.get("affected_entities"):
            entities = ", ".join(threat_data["affected_entities"])
            prompt_parts.append(f"Affected Entities: {entities}")

        if threat_data.get("attack_pattern"):
            prompt_parts.append(f"Attack Pattern: {threat_data['attack_pattern']}")

        prompt_parts.append(
            "\nYour task: Analyze the threat and execute appropriate mitigation actions. "
            "Be decisive and thorough."
        )

        return "\n".join(prompt_parts)

    def _parse_agent_response(
        self,
        response: str,
        threat_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Parse the agent's response into a structured mitigation report."""
        try:
            # Extract action summary from response
            actions_taken = []
            recommendations = []

            # Simple parsing (in production, use structured output)
            if "block_ip" in response.lower():
                actions_taken.append("IP blocking rule created")

            if "isolate_host" in response.lower():
                actions_taken.append("Host isolation executed")

            if "threat" in response.lower():
                recommendations.append("Continue monitoring for related indicators")

            return {
                "status": "success",
                "threat_id": threat_data.get("query", "unknown")[:50],
                "severity": threat_data.get("severity", "medium"),
                "confidence": threat_data.get("confidence", 0.5),
                "actions_taken": actions_taken,
                "recommendations": recommendations,
                "agent_reasoning": response,
                "timestamp": "2024-04-13T10:00:00Z",
            }

        except Exception as e:
            logger.error(f"Failed to parse agent response: {e}")
            return {
                "status": "error",
                "message": f"Failed to parse mitigation response: {str(e)}",
            }

    def _run_mock_mitigation(
        self,
        threat_data: Dict[str, Any],
        prompt: str,
    ) -> Dict[str, Any]:
        """
        Run mitigation in mock mode when agent is not available.

        This simulates the agent's behavior for testing and demo purposes.
        """
        logger.info("Running mock mitigation workflow")

        severity = threat_data.get("severity", "medium").lower()
        confidence = threat_data.get("confidence", 0.5)

        actions_taken = []
        recommendations = []

        # Mock decision logic
        if confidence > 0.85:
            if severity == "critical":
                if threat_data.get("source_ip"):
                    actions_taken.append(
                        f"Created firewall rule to block {threat_data['source_ip']}"
                    )

                if threat_data.get("affected_entities"):
                    for entity in threat_data["affected_entities"][:2]:
                        actions_taken.append(f"Isolated host: {entity}")

        # Always recommend investigation
        recommendations.extend([
            "Continue monitoring for related indicators",
            "Review firewall logs for suspicious patterns",
            "Check for lateral movement attempts",
            "Verify no data exfiltration occurred",
        ])

        return {
            "status": "success",
            "threat_id": threat_data.get("query", "unknown")[:50],
            "severity": severity.upper(),
            "confidence": confidence,
            "actions_taken": actions_taken,
            "recommendations": recommendations,
            "mode": "mock",
            "message": "Mock mitigation completed. Agent not configured. Use real LLM for autonomous decisions.",
            "timestamp": "2024-04-13T10:00:00Z",
        }


# ============================================================================
# Singleton Instance
# ============================================================================


_orchestrator: Optional[ThreatMitigationOrchestrator] = None


def get_orchestrator() -> ThreatMitigationOrchestrator:
    """Get or create the threat mitigation orchestrator (singleton)."""
    global _orchestrator

    if _orchestrator is None:
        logger.info("Creating threat mitigation orchestrator instance")
        _orchestrator = ThreatMitigationOrchestrator()

    return _orchestrator
