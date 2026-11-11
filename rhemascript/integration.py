"""Synthetic end-to-end orchestration for contract-level system verification."""
from rhemascript.capabilities import CapabilityEngine
from rhemascript.interfaces import InterfaceGateway
from rhemascript.core.envelope import validate_record

class SyntheticWorkflow:
    def __init__(self): self.capabilities=CapabilityEngine(); self.interfaces=InterfaceGateway()
    def run(self, project_record, *, capability_evidence, actor_role='TEST_HARNESS'):
        validate_record(project_record)
        cap_results=[]
        for cap_id in self.capabilities.registry:
            cap_results.append(self.capabilities.execute(cap_id,project_record,
                actor_role=actor_role,evidence=capability_evidence.get(cap_id,{})))
        interface_results=[]
        for iid in self.interfaces.adapters:
            req={'request_id':f'{project_record["project_id"]}-{iid}',
                 'project_id':project_record['project_id'],'operation':'VALIDATE',
                 'payload':{'synthetic':True,'interface_id':iid},'source_version':'synthetic-v1'}
            interface_results.append(self.interfaces.invoke(iid,req))
        return {'project_id':project_record['project_id'],
                'capability_results':cap_results,'interface_results':interface_results,
                'capabilities_exercised':len(cap_results),'interfaces_exercised':len(interface_results),
                'status':'SYNTHETIC_CONTRACT_FLOW_COMPLETE'}
