"""18 registered runtime interface adapters. No external network calls or writes occur."""
from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any
from rhemascript.registry.system_registry import INTERFACES
from rhemascript.core.disclosure import disclose, DisclosureError
from rhemascript.core.authority import authorise_action, AuthorityError

class InterfaceError(ValueError): pass

@dataclass(frozen=True)
class InterfaceResponse:
    interface_id: str
    status: str
    request_id: str
    payload: dict[str, Any]
    idempotency_key: str

class InterfaceGateway:
    def __init__(self):
        self.adapters={iid:self._handle for iid in INTERFACES}
        self._seen={}

    def invoke(self, interface_id: str, request: dict[str,Any], *,
               recipient_clearance: str='OPERATIONAL', task_need: bool=True,
               approved_scope: bool=True, authority: dict[str,bool]|None=None) -> InterfaceResponse:
        if interface_id not in self.adapters: raise InterfaceError('unknown interface')
        if not isinstance(request,dict): raise InterfaceError('request must be an object')
        required=('request_id','project_id','operation','payload','source_version')
        missing=[k for k in required if k not in request]
        if missing: raise InterfaceError('missing request fields: '+', '.join(missing))
        for key in ('request_id','project_id','operation','source_version'):
            if not isinstance(request[key],str) or not request[key].strip():
                raise InterfaceError(f'{key} must be a non-empty string')
        if not isinstance(request['payload'],dict): raise InterfaceError('payload must be an object')
        classification=request.get('classification','OPERATIONAL')
        try:
            disclose(item_classification=classification,recipient_clearance=recipient_clearance,
                     task_need=task_need,approved_scope=approved_scope)
        except DisclosureError as exc: raise InterfaceError(str(exc)) from exc
        operation=request['operation'].upper()
        if operation in {'GENERATE','PUBLISH','SPEND','EXTERNAL_WRITE'}:
            try: authorise_action(operation,authority or {})
            except AuthorityError as exc: raise InterfaceError(str(exc)) from exc
        canonical=json.dumps(request,sort_keys=True,separators=(',',':'),default=str)
        key=sha256(canonical.encode()).hexdigest()
        if key in self._seen: return self._seen[key]
        result=self._handle(interface_id,request,key)
        self._seen[key]=result
        return result

    @staticmethod
    def _handle(interface_id,request,key):
        return InterfaceResponse(interface_id,'ACCEPTED_FOR_LOCAL_PROCESSING',request['request_id'],
            {'project_id':request['project_id'],'operation':request['operation'],
             'source_version':request['source_version'],'payload':request['payload']},key)
