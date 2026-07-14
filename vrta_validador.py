import sys
import json
import os

# Pega o caminho do arquivo SARIF
arquivo_sast = sys.argv[1] if len(sys.argv) > 1 else './output.sarif'

# 1. MAPEAMENTO DA CARTILHA DE QA (MUST HAVE)
# Mapeamos o ID do requisito para o código numérico do CWE
cartilha_must_have = {
    "89": "M-REQ-001 (SQL Injection)",
    "77": "M-REQ-001 (Command Injection)",
    "90": "M-REQ-001 (LDAP Injection)",
    "611": "M-REQ-001 (XML External Entity - XXE)",
    "74": "M-REQ-001 (JSON/XML Injection)",
    "94": "M-REQ-001 (Code Injection)",
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

print("=== INICIANDO VALIDAÇÃO DE REQUISITOS (VRTA) ===")

# Vamos criar um dicionário de regras indexado pelo ID da regra para buscar os metadados dela
regras_meta = {}
for run in sast_data.get('runs', []):
    resources = run.get('tool', {}).get('driver', {})
    for rule in resources.get('rules', []):
        regras_meta[rule.get('id')] = rule

# 2. VARREDURA DE ACHADOS
for run in sast_data.get('runs', []):
    for result in run.get('results', []):
        rule_id = result.get('ruleId', '')
        
        # Pega a mensagem de erro que descreve a vulnerabilidade
        mensagem = result.get('message', {}).get('text', '')
        
        # Pega as propriedades e tags da regra associada
        regra_associada = regras_meta.get(rule_id, {})
        tags_da_regra = regra_associada.get('properties', {}).get('tags', [])
        short_description = regra_associada.get('shortDescription', {}).get('text', '')
        help_uri = regra_associada.get('helpUri', '')

        # Unifica todo o texto que possa conter uma menção ao CWE (ex: "CWE-89", "cwe:89", "CWE: 89")
        texto_busca = str([rule_id, mensagem, tags_da_regra, short_description, help_uri]).upper()

        # Verifica se algum dos CWEs mapeados na cartilha está presente no texto descritivo do achado
        for cwe_num, req_desc in cartilha_must_have.items():
            # Cria padrões comuns de escrita de CWE para buscar no texto
            padroes_cwe = [f"CWE-{cwe_num}", f"CWE:{cwe_num}", f"CWE_{cwe_num}", f"CWE {cwe_num}"]
            
            padrone_encontrado = False
            for padrao in padroes_cwe:
                if padrao in texto_busca:
                    padrone_encontrado = True
                    break
                    
            if padrone_encontrado:
                try:
                    local = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
                    linha = result['locations'][0]['physicalLocation']['region']['startLine']
                except (KeyError, IndexError):
                    local, linha = "Desconhecido", "?"
                
                msg = f"Falha de Requisito: {req_desc} violado no arquivo {local} (Linha {linha})."
                if msg not in violacoes:
                    violacoes.append(msg)

# 3. DECISÃO DA PIPELINE
if violacoes:
    print(f"\n[BLOQUEADO] Foram encontradas {len(violacoes)} violações de Requisitos de Segurança (MUST HAVE)!\n")
    for v in violacoes:
        print(f"::error::{v}")
    print("\nPipeline bloqueada pelo Quality Gate de Segurança do QA!")
    sys.exit(1)
else:
    print("\n[SUCESSO] Validação VRTA concluída. O código está aderente aos requisitos de segurança da cartilha.")
    sys.exit(0)