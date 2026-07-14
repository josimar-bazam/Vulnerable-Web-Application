import sys
import json
import os
import re

# Pega o caminho do arquivo SARIF
arquivo_sast = sys.argv[1] if len(sys.argv) > 1 else './output.sarif'

# 1. MAPEAMENTO COMPLETO DA CARTILHA DE QA (MUST HAVE)
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

print("=== DIAGNÓSTICO DE LEITURA DO SARIF ===")
print(f"Diretório atual: {os.getcwd()}")
print(f"Verificando arquivo: {arquivo_sast}")

if not os.path.exists(arquivo_sast):
    print(f"::error::Arquivo {arquivo_sast} NÃO foi encontrado!")
    sys.exit(1)

tamanho = os.path.getsize(arquivo_sast)
print(f"Tamanho do arquivo lido: {tamanho} bytes")

try:
    with open(arquivo_sast, 'r') as f:
        conteudo_completo = f.read()
        sast_data = json.loads(conteudo_completo)
    print("Sucesso: JSON do SARIF carregado na memória!")
except Exception as e:
    print(f"::error::Falha crítica ao decodificar JSON do SARIF: {e}")
    sys.exit(1)

runs = sast_data.get('runs', [])
print(f"Quantidade de 'runs' no arquivo: {len(runs)}")

# Varredura Global de Segurança (Fallback e Verificação de Conteúdo)
cwes_globais = set(re.findall(r'(?i)CWE[-_:\s]?(\d+)', conteudo_completo))
print(f"CWEs encontrados em todo o texto bruto do arquivo: {list(cwes_globais)}")

violacoes = []
regras_meta = {}

# Mapeia metadados de regras
for run in runs:
    driver = run.get('tool', {}).get('driver', {})
    for rule in driver.get('rules', []):
        regras_meta[rule.get('id')] = rule
print(f"Mapeadas {len(regras_meta)} definições de regras de metadados.")

# 2. VARREDURA DE ACHADOS POR REGEX INDIVIDUAL
total_resultados = 0
for run in runs:
    results = run.get('results', [])
    total_resultados += len(results)
    for result in results:
        rule_id = result.get('ruleId', '')
        
        # Concatena o achado e os metadados da regra para busca contextual
        objeto_completo_str = json.dumps(result)
        if rule_id in regras_meta:
            objeto_completo_str += " " + json.dumps(regras_meta[rule_id])
        
        # Procura por menções a CWEs no escopo deste achado
        cwes_encontrados = list(set(re.findall(r'(?i)CWE[-_:\s]?(\d+)', objeto_completo_str)))
        
        for cwe_num in cwes_encontrados:
            if cwe_num in cartilha_must_have:
                req_desc = cartilha_must_have[cwe_num]
                
                try:
                    local = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
                    linha = result['locations'][0]['physicalLocation']['region']['startLine']
                except (KeyError, IndexError):
                    local, linha = "Desconhecido", "?"
                
                try:
                    titulo = result.get('message', {}).get('text', rule_id).split('\n')[0][:80]
                except:
                    titulo = rule_id
                
                msg = f"Falha de Requisito: {req_desc} violado -> [{titulo}] no arquivo {local} (Linha {linha}) [CWE-{cwe_num}]"
                if msg not in violacoes:
                    violacoes.append(msg)

print(f"Total de vulnerabilidades avaliadas individualmente no arquivo: {total_resultados}")
print("========================================\n")

# 3. TOMADA DE DECISÃO DA PIPELINE
if violacoes:
    print(f"[BLOQUEADO] Foram encontradas {len(violacoes)} violações de Requisitos de Segurança (MUST HAVE)!\n")
    for v in violacoes:
        print(f"::error::{v}")
    print("\nPipeline bloqueada pelo Quality Gate de Segurança do QA!")
    sys.exit(1)
else:
    print("[SUCESSO] Validação VRTA concluída. O código está aderente aos requisitos de segurança da cartilha.")
    sys.exit(0)