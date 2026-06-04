import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from mirage.layer2_attack_graph import build_enterprise_attack_graph
from mirage.attacker_agents import run_simulation

graph = build_enterprise_attack_graph()
print('Testing all attacker types (no defense)...')
for atype in ['random', 'greedy', 'shortest_path', 'stealthy']:
    result = run_simulation(graph, atype, n_episodes=300, seed=42)
    ht = result['hit_true_goal_rate']
    di = result['decoy_interception_rate']
    st = result['avg_steps_to_terminal']
    print(f'{atype:20s}: Hit TG={ht:.1%}  Decoy={di:.1%}  Steps={st:.1f}')

print('\nTesting WITH deception (Fake DB reward=0.9)...')
interventions = {(11, 'end'): 0.9, (12, 'end'): 0.7}
for atype in ['random', 'greedy', 'shortest_path', 'stealthy']:
    result = run_simulation(graph, atype, n_episodes=300, seed=42, reward_interventions=interventions)
    ht = result['hit_true_goal_rate']
    di = result['decoy_interception_rate']
    st = result['avg_steps_to_terminal']
    print(f'{atype:20s}: Hit TG={ht:.1%}  Decoy={di:.1%}  Steps={st:.1f}')
