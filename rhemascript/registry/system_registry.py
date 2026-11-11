CAPABILITIES = {'CAP-01': 'Biblical Source Intelligence & Evidence Graph', 'CAP-02': 'Biblical Interpretation Risk Review', 'CAP-03': 'Scripture-to-Story Integrity Mapping', 'CAP-04': 'Content Opportunity Scoring', 'CAP-05': 'Narrative Simulation & Creative Challenge', 'CAP-06': 'Audience Learning Loop', 'CAP-07': 'Visual Continuity Intelligence', 'CAP-08': 'Pre-Production Simulation & Feasibility', 'CAP-09': 'Adaptive Production Tool Intelligence', 'CAP-10': 'Asset Intelligence & Recovery', 'CAP-11': 'Multi-Dimensional Quality Scoring', 'CAP-12': 'AI Security & Trust Framework', 'CAP-13': 'Rights, Provenance & Content Authenticity', 'CAP-14': 'Production Failure Intelligence', 'CAP-15': 'Performance-to-Production Learning'}
INTERFACES = tuple(f'IF-{i:02d}' for i in range(1, 19))
REQUIRED_GATES = (
    'PROJECT_CREATIVE_DIRECTION', 'SCRIPT_BIBLICAL_ACCURACY',
    'VISUAL_DEVELOPMENT', 'PRODUCTION_PLAN_PROMPT',
    'GENERATION_AUTHORISATION', 'FINAL_FILM'
)
SEPARATE_AUTHORITIES = (
    'APPROVAL', 'EXECUTION_AUTHORISATION', 'FINAL_ACCEPTANCE',
    'PUBLISHING_AUTHORISATION'
)
