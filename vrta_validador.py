import sys
import json
import os
import re

# Pega o caminho do arquivo SARIF
arquivo_sast = sys.argv[1] if len(sys.argv) > 1 else './output.sarif'

# 1. MAPEAMENTO COMPLETO DA CARTILHA DE QA (MUST HAVE)
# Mapeamos o ID do requisito para o número bruto do CWE
cartilha_must_have = {
    "89": "M-REQ-001 (SQL Injection)",
    "77": "M-REQ-001 (Command Injection)",
    "78": "M-REQ-001 (OS Command Injection)",
    "90": "M-REQ-001 (LDAP Injection)",
    "611": "M-REQ-001 (XML External Entity - XXE)",
    "74": "M-REQ-001 (JSON/XML Injection)",
    "94": "M-REQ-001 (Code Injection)",
    "98": "M-REQ-001 (Local/Remote File Inclusion - LFI/RFI)",
    "22": "M-REQ-001 (Path Traversal)",
    "79": "M-REQ-002 (Cross-Site Scripting - XSS)",
    "693": "M-REQ-002 (Clickjacking / UI Redressing)",
    "116": "M-REQ-002 (Improper Encoding)",
    "798": "M-REQ-003 (Credenciais Hardcoded)",
    "256": "M-REQ-003 (Senhas em Texto Claro)",
    "532": "M-REQ-003 (Vazamento em Logs)",
    "327": "M-REQ-003 (Algoritmo Criptográfico Obsoleto)",
    "319": "M-REQ-003 (Tráfego Inseguro em Texto Claro)",
    "862": "M-REQ-004 (BOLA / IDOR)",
    "863": "M-REQ-004 (Broken Access Control)",
    "266": "M-REQ-004 (Privilégios Excessivos)",
    "915": "M-REQ-004 (Mass Assignment)",
    "732": "M-REQ-004 (Privileged Container/Misconfiguration)",
    "250": "M-REQ-004 (Execution with Unnecessary Privileges)"
}

if not os.path.exists(arquivo_sast):
    print("::warning::Arquivo SARIF não encontrado.")
    sys.exit(0)

with open(arquivo_sast, 'r') as f:
    sast_data = json.load(f)

violacoes = []
regras_meta = {}

# Mapeia as regras globais do SARIF para buscar descrições amigáveis depois
for run in sast_data.get('runs', []):
    driver = run.get('tool', {}).get('driver', {})
    for rule in driver.get('rules', []):
        regras_meta[rule.get('id')] = rule

print("=== INICIANDO VARREDURA PROFUNDA DE REQUISITOS (VRTA) ===")

# 2. VARREDURA DE ACHADOS COM REGEX
for run in sast_data.get('runs', []):
    for result in run.get('results', []):
        rule_id = result.get('ruleId', '')
        
        # Converte o bloco inteiro de resultado e os metadados da regra em texto string
        objeto_completo_str = json.dumps(result)
        if rule_id in regras_meta:
            objeto_completo_str += " " + json.dumps(regras_meta[rule_id])
        
        # Expressão Regular para capturar qualquer menção a CWE (Ex: CWE-89, cwe:78, CWE_98, CWE 89)
        cwes_encontrados = re.findall(r'(?i)CWE[-_:\s]?(\d+)', objeto_completo_str)
        
        # Remove duplicatas encontradas para este mesmo achado
        cwes_encontrados = list(set(cwes_encontrados))
        
        # Valida contra as regras críticas de QA
        for cwe_num in cwes_encontrados:
            if cwe_num in cartilha_must_have:
                req_desc = cartilha_must_have[cwe_num]
                
                # Tenta buscar a localização do erro no código
                try:
                    local = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
                    linha = result['locations'][0]['physicalLocation']['region']['startLine']
                except (KeyError, IndexError):
                    local, linha = "Desconhecido", "?"
                
                # Tenta buscar o título amigável da vulnerabilidade
                try:
                    titulo = regras_meta.get(rule_id, {}).get('shortDescription', {}).get('text', rule_id)
                except:
                    titulo = rule_id
                
                msg = f"Falha de Requisito: {req_desc} violado -> [{titulo}] no arquivo {local} (Linha {linha}) [CWE-{cwe_num}]"
                if msg not in violacoes:
                    violacoes.append(msg)

# 3. TOMADA DE DECISÃO DA PIPELINE
if violacoes:
    print(f"\n[BLOQUEADO] Foram encontradas {len(violacoes)} violações de Requisitos de Segurança (MUST HAVE)!\n")
    for v in violacoes:
        print(f"::error::{v}")
    print("\nPipeline bloqueada pelo Quality Gate de Segurança do QA!")
    sys.exit(1)
else:
    print("\n[SUCESSO] Validação VRTA concluída. O código está aderente aos requisitos de segurança da cartilha.")
    sys.exit(0)