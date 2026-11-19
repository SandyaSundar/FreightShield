import os


from crewai import LLM
from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai_tools import (
	ExaSearchTool
)
from ai_soc_copilot___wazuh_investigator.tools.wazuh_readonly_query_tool import WazuhReadOnlyQueryTool





@CrewBase
class AiSocCopilotWazuhInvestigatorCrew:
    """AiSocCopilotWazuhInvestigator crew"""

    
    @agent
    def wazuh_alert_investigator(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["wazuh_alert_investigator"],
            
            
            tools=[				WazuhReadOnlyQueryTool()],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=LLM(
                model="openai/gpt-5.6-luna",
                
                
            ),
            
        )
        
    
    @agent
    def threat_analyzer(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["threat_analyzer"],
            
            
            tools=[				ExaSearchTool()],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=LLM(
                model="openai/gpt-5.6-luna",
                
                
            ),
            
        )
        
    
    @agent
    def response_advisor(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["response_advisor"],
            
            
            tools=[],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=LLM(
                model="openai/gpt-5.6-luna",
                
                
            ),
            
        )
        
    

    
    @task
    def collect_wazuh_evidence_for_investigation_request(self) -> Task:
        return Task(
            config=self.tasks_config["collect_wazuh_evidence_for_investigation_request"],
            markdown=False,
            
            
        )
    
    @task
    def analyze_threat_for_investigation_request(self) -> Task:
        return Task(
            config=self.tasks_config["analyze_threat_for_investigation_request"],
            markdown=False,
            
            
        )
    
    @task
    def write_investigation_report_for_investigation_request(self) -> Task:
        return Task(
            config=self.tasks_config["write_investigation_report_for_investigation_request"],
            markdown=False,
            
            
        )
    

    @crew
    def crew(self) -> Crew:
        """Creates the AiSocCopilotWazuhInvestigator crew"""

        return Crew(
            agents=self.agents,  # Automatically created by the @agent decorator
            tasks=self.tasks,  # Automatically created by the @task decorator
            process=Process.sequential,
            verbose=True,

            chat_llm=LLM(model="openai/gpt-5.6-luna"),
        )


